#!/usr/bin/env python3
"""Fake ICMP echo responder, used to make the example images in docs/.

TEST ONLY. It answers pings sent to 127.0.0.2 - 127.0.0.5 with made-up
delays, so we can show what pingem displays in situations that are hard to
produce on demand: traffic split over two routes, a jittery access link, and
so on. It never touches real traffic.

Run as root, on a machine where you don't mind ping replies being turned off
for a while - the kernel must not answer the pings itself:

    sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
    sudo ./fake_responder.py routing        # or: perpacket, mixed, hops
    ...
    sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0

Scenarios (how each fake reply is delayed):

  routing    Two "routes", ~3 ms and ~9 ms. Which one a ping takes depends
             only on its ICMP checksum, the way a load-balancing router
             hashes headers. So every pingem flow sticks to one route. The
             slow route also drops 4% of packets.
  perpacket  The same two delays, but chosen at random for every packet, the
             way a cable modem's transmit schedule or Wi-Fi retries behave.
             The checksum makes no difference.
  mixed      Some checksums get a fixed route, others are re-rolled every
             packet - e.g. two balancers in a row, one of them per-packet.
  hops       Four hops of one path, at 127.0.0.2 .. .5: a home router
             (~0.3 ms), the ISP's box (~1.2 ms), the far end of a cable link
             (~11 ms, with banded jitter), and a server beyond it (+1.5 ms).
  routes     A whole fake network, for the route view. Pings to 127.0.0.10
             cross six "routers" at 127.0.1.x, which answer TTL-limited
             probes with Time Exceeded, the way real ones do:

               TTL 1   127.0.1.1                  home router
               TTL 2   127.0.1.2                  ISP
               TTL 3   127.0.1.3 | 127.0.1.4      load balanced by checksum
               TTL 4   (never answers: "*")
               TTL 5   127.0.1.6 | 127.0.1.7      balanced again, other hash
               TTL 6   127.0.0.10                 the target

             127.0.0.11 is the same network, except that 127.0.1.2 refuses
             one ping in five with "Destination Unreachable (host)".

             Two more endpoints, for the all-routes map:
               127.0.0.12  splits off after 127.0.1.2: 127.0.1.8, then
                           127.0.1.9 - and every 45 seconds its third hop
                           flips between 127.0.1.8 and 127.0.1.12, a
                           route change.
               127.0.0.13  shares the balanced third hop and the silent
                           fourth, then goes its own way: 127.0.1.10,
                           127.0.1.11.
               127.0.0.14  a long way off, like a big search engine: after
                           the ISP, three hops that never answer, then a
                           chain of eight routers, 127.0.2.1 - 127.0.2.8.
               127.0.0.15  leaves everyone else right after the home router,
                           through the ISP's other boxes - and the box there
                           balances by ICMP *identifier*, not checksum (as
                           real ones do): 127.0.1.13 or 127.0.1.16, then
                           127.0.1.14, 127.0.1.15.

             And the home router, 127.0.1.1, is rate-limited: it answers
             only about half the probes that run out of TTL there, the way
             many home routers do.
"""

import hashlib
import heapq
import random
import socket
import struct
import sys
import threading
import time

ADDRESSES = ['127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5',
             '127.0.0.10', '127.0.0.11', '127.0.0.12', '127.0.0.13']
ADDRESSES.append('127.0.0.14')
ADDRESSES.append('127.0.0.15')
ROUTERS = (['127.0.1.%d' % n for n in range(1, 17)] +
           ['127.0.2.%d' % n for n in range(1, 9)])
ROUTE_TARGETS = ('127.0.0.10', '127.0.0.11', '127.0.0.12', '127.0.0.13', '127.0.0.14',
                 '127.0.0.15')


def hash_bit(checksum, which):
    """A stable pseudo-random bit per checksum - our stand-in router hash."""
    return hashlib.md5(struct.pack('!H', checksum)).digest()[which] & 1


def jitter(spread):
    return random.gauss(0.0, spread)


def cable_delay():
    """A DOCSIS-like upstream: a base delay, plus 0, 1 or 2 whole 2.5 ms
    "wait for the next transmit opportunity" steps, plus a smear within the
    step."""
    steps = random.choices([0, 1, 2], weights=[5, 3, 1])[0]
    return 0.0085 + steps * 0.0025 + random.uniform(0.0, 0.002)


def delay_for(scenario, destination, checksum):
    """Seconds to wait before replying, or None to drop the packet."""
    fast = 0.003 + jitter(0.0004)
    slow = 0.009 + jitter(0.0004)
    if scenario == 'routing':
        if hash_bit(checksum, 0):
            return None if random.random() < 0.04 else slow
        return fast
    if scenario == 'perpacket':
        return slow if random.random() < 0.5 else fast
    if scenario == 'mixed':
        if hash_bit(checksum, 1):
            return slow if random.random() < 0.5 else fast   # re-rolled
        return slow if hash_bit(checksum, 0) else fast       # fixed route
    if scenario == 'hops':
        if destination == '127.0.0.2':
            return 0.0003 + abs(jitter(0.00005))
        if destination == '127.0.0.3':
            return 0.0012 + abs(jitter(0.0002))
        if destination == '127.0.0.4':
            return cable_delay()
        return cable_delay() + 0.0015 + abs(jitter(0.0002))
    return fast


def route_answer(destination, checksum, ttl, identifier=0):
    """For the routes scenario: (who answers, ICMP type, code, delay), or
    None for silence. Type 0 is the target's echo reply; 11 is a router's
    Time Exceeded; 3 is Destination Unreachable."""
    balanced = '127.0.1.4' if hash_bit(checksum, 0) else '127.0.1.3'
    if destination == '127.0.0.12':
        flipped = int(time.time() / 45) % 2
        path = ['127.0.1.1', '127.0.1.2', '127.0.1.12' if flipped else '127.0.1.8',
                '127.0.1.9']
    elif destination == '127.0.0.15':
        by_identifier = hashlib.md5(struct.pack('!H', identifier)).digest()[0] & 1
        path = ['127.0.1.1', '127.0.1.16' if by_identifier else '127.0.1.13',
                '127.0.1.14', '127.0.1.15']
    elif destination == '127.0.0.14':
        path = (['127.0.1.1', '127.0.1.2', None, None, None] +
                ['127.0.2.%d' % n for n in range(1, 9)])
    elif destination == '127.0.0.13':
        path = ['127.0.1.1', '127.0.1.2', balanced, None, '127.0.1.10', '127.0.1.11']
    else:
        path = ['127.0.1.1', '127.0.1.2', balanced, None,
                '127.0.1.7' if hash_bit(checksum, 2) else '127.0.1.6']
    # Each hop adds about a millisecond; the .4 branch adds 5 more.
    delays = [0.0004 + 0.0011 * n for n in range(len(path))]
    extra = 0.005 if hash_bit(checksum, 0) and destination != '127.0.0.12' else 0.0
    if destination == '127.0.0.11' and ttl >= 2 and random.random() < 0.2:
        return ('127.0.1.2', 3, 1, 0.0013 + abs(jitter(0.0002)))
    if ttl <= len(path):
        router = path[ttl - 1]
        if router is None:
            return None
        if router == '127.0.1.1' and random.random() < 0.5:
            return None   # rate-limited
        delay = delays[ttl - 1] + (extra if ttl >= 3 else 0.0) + abs(jitter(0.0002))
        return (router, 11, 0, delay)
    return (destination, 0, 0, 0.0012 * len(path) + 0.0012 + extra + abs(jitter(0.0003)))


def internet_checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def main():
    scenario = sys.argv[1] if len(sys.argv) > 1 else 'routing'
    listener = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # One sending socket per fake address, so replies come FROM that address.
    senders = {}
    for address in ADDRESSES + ROUTERS:
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sender.bind((address, 0))
        senders[address] = sender

    # Replies wait in a heap ordered by when they're due, and one thread sends
    # them. (A thread per reply works too, but under load Python's thread
    # start-up adds stray delays of tens of milliseconds - outliers that would
    # stretch the graphs' RTT scale.)
    due = []
    due_lock = threading.Condition()

    def sender_loop():
        while True:
            with due_lock:
                while not due:
                    due_lock.wait()
                when, _, sender, reply, requester = due[0]
                wait = when - time.monotonic()
                if wait > 0:
                    due_lock.wait(min(wait, 0.0005))
                    continue
                heapq.heappop(due)
            reply = bytearray(reply)
            reply[2] = reply[3] = 0
            checksum = internet_checksum(bytes(reply))
            reply[2], reply[3] = checksum >> 8, checksum & 0xff
            sender.sendto(bytes(reply), (requester, 0))

    threading.Thread(target=sender_loop, daemon=True).start()
    counter = 0

    while True:
        packet = listener.recv(65535)
        header_length = (packet[0] & 0x0f) * 4
        icmp = packet[header_length:]
        source = socket.inet_ntoa(packet[12:16])
        destination = socket.inet_ntoa(packet[16:20])
        if icmp[0] != 8 or destination not in senders:
            continue
        checksum = struct.unpack('!H', icmp[2:4])[0]
        if scenario == 'routes':
            if destination not in ROUTE_TARGETS:
                continue
            identifier = struct.unpack('!H', icmp[4:6])[0]
            answer = route_answer(destination, checksum, packet[8], identifier)
            if answer is None:
                continue
            responder, kind, code, delay = answer
            if kind == 0:
                reply = bytes([0]) + icmp[1:]
            else:
                # An ICMP error quotes the offending packet's IP header and
                # the first 8 bytes of its payload (RFC 792).
                reply = (bytes([kind, code, 0, 0, 0, 0, 0, 0]) +
                         packet[:header_length + 8])
        else:
            delay = delay_for(scenario, destination, checksum)
            if delay is None:
                continue
            responder = destination
            reply = bytes([0]) + icmp[1:]    # echo reply
        counter += 1
        with due_lock:
            heapq.heappush(due, (time.monotonic() + max(delay, 0.0), counter,
                                 senders[responder], reply, source))
            due_lock.notify()


if __name__ == '__main__':
    main()
