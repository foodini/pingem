#!/usr/bin/env python3

# TODO, High Priority:
# * Switch domain socket comms output to be human-readable so people using it as
#   a ping replacement (like via socat) can grok it better.
# * need to chroot jail the process
# * handle Destination Net Unreachable.

#TODO, Medium Priority:
# * connection_id isn't quite enough to ID a packet. What if there are two instances
#   of user_icmp running at the same time? Each could have a caller on connection_id=5
#   and the two instance would confuse the other's responses as their own.
# * need to consider defense against abusers. I have a brief delay before
#   sending starts, but I should keep a token bucket for each user and allow
#   admin to set the refil rate and count.

# TODO: Low Priority:
# * Should I stop sending connection_id over the network? Writting a mapper just adds
#   more code that has to run in privileged mode.
# * Do I need a defense against bursting? If 100 targets are added at the same
#   time with the same interval, they're going to tend to affect each other.
# * Track the number of times bump() has been called since a target was created.
#   Slightly alter the ACTUAL amount we bump by to try to meet the average?
# * Should it be left to the user to determine RTT? If so, I can save 8 bytes.
#   Given that the current minimum packet size is 34, it's hard to justify.

from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from queue import PriorityQueue, Queue
import random
import re
import socket
import struct
import threading
import time
from urllib.parse import urlparse, parse_qs

MAX_PACKET_SIZE = 8192
MAGIC_STRING = bytes('867-5309', 'utf-8')
MAGIC_STRING_LEN = len(MAGIC_STRING)

class ICMP():
  def to_dotted_ip(self, long):
    return f'{(long>>24) % 256}.{(long>>16) % 256}.{(long>>8) % 256}.{(long) % 256}'

class Ping(ICMP):
  def __init__(self, resolved_address, connection_id, icmp_seq, timestamp):
    self.resolved_address = resolved_address
    self.connection_id = connection_id
    self.icmp_seq = icmp_seq
    self.timestamp = timestamp

  def __str__(self):
    return('{' + f'"type":"ping", "to":"{self.resolved_address}", "icmp_seq":"{self.icmp_seq}", ' +
           f'"timestamp":"{self.timestamp}"' + '}')

class Pong(ICMP):
  def __init__(self, connection_id, icmp_seq, timestamp, rtt, source_ip, ttl):
    self.connection_id = connection_id
    self.icmp_seq = icmp_seq
    self.timestamp = timestamp
    self.rtt = rtt
    self.source_ip = source_ip
    self.ttl = ttl

  def __str__(self):
    dotted_ip = self.to_dotted_ip(self.source_ip)
    return ('{' + f'"type":"reply", "from":"{dotted_ip}", "icmp_seq":"{self.icmp_seq}", ' +
            f'"timestamp":"{self.timestamp}", "rtt":"{self.rtt}", "ttl":"{self.ttl}"' + '}')

#TODO: derive a Target type for handling traceroutes
class Target():
  def __init__(self, unresolved_address, resolved_address, connection_id, packet_size, interval):
    self.unresolved_address = unresolved_address
    self.resolved_address = resolved_address
    self.connection_id = connection_id
    self.packet_size = packet_size
    self.interval = interval
    self.icmp_seq = 1

  def __str__(self):
    return f'{self.unresolved_address} {self.resolved_address} fd:{self.connection_id}'

  def bump(self):
    self.next_ping_time += self.interval
    self.icmp_seq += 1

class SocketManager():
  def __init__(self):
    self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    self.ip_header_size = 20
    self.icmp_header_size = 8
    # magic, connection_id, icmp_seq, timestamp
    self.user_ping_header_size = MAGIC_STRING_LEN + 2 + 8 + 8
    self.all_header_size = self.user_ping_header_size + self.icmp_header_size + self.ip_header_size

  def calc_checksum(self, icmp_packet):
    checksum = 0
    for i in range(0, len(icmp_packet), 2):
      checksum += (icmp_packet[i] << 8) + (
        struct.unpack('B', icmp_packet[i + 1:i + 2])[0]
        if len(icmp_packet[i + 1:i + 2]) else 0
      )

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

  def build_icmp(self, payload, connection_id, icmp_seq):
    now = time.time()
    icmp_packet = (struct.pack(
        f'!BBHHH{MAGIC_STRING_LEN}sHQd',
        #type, code, checksum, identifier, seq number
        8, 0, 0, 12345, icmp_seq % 65536,
        MAGIC_STRING, connection_id, icmp_seq, now)
        + payload
    )
    c = self.calc_checksum(icmp_packet)
    icmp_packet = (struct.pack(
        f'!BBHHH{MAGIC_STRING_LEN}sHQd',
        #type, code, checksum, identifier, seq number
        8, 0, c, 12345, icmp_seq % 65536,
        MAGIC_STRING, connection_id, icmp_seq, now)
        + payload
    )

    return icmp_packet, now

  #TODO: if "destination" is an ip name with multiple associated ip addresses (like amazon.com),
  #      sendto will arbitrarily choose between them with each packet. Kinda need to fix this.
  def send(self, resolved_address, connection_id, icmp_seq, length):
    # TODO: don't build the pad every time. Stash it in the target or something.
    payload = bytes('x', 'utf-8') * (length - self.icmp_header_size - self.user_ping_header_size)
    packet, timestamp = self.build_icmp(payload, connection_id, icmp_seq)
    self.raw_socket.sendto(packet, (resolved_address, 0))

    return Ping(resolved_address, connection_id, icmp_seq, timestamp)

  def tick(self, timeout_time):
    try:
      response, _ = self.raw_socket.recvfrom(MAX_PACKET_SIZE+1024)
      now = time.time()
      # TODO: check response len to ensure it is at least the size of the user_icmp header!!!
      icmp_type = struct.unpack('!B', response[20:21])[0]
      if icmp_type == 0:
        (
            version_and_header_length, tos, total_length,
            identifier, flags_and_frag_off,
            ttl, protocol, header_checksum,
            source_addr,
            dest_addr,
            #end of IP header
            icmp_type, code, icmp_checksum,
            identifier, _icmp_seq,
            #end of ICMP header
            magic_string, connection_id, icmp_seq, timestamp
        ) = struct.unpack(
            '!'
            'BBH'
            'HH'
            'BBH'
            'L'
            'L'
            #end of IP header
            'BBH'
            'HH'
            #end of IP/ICMP header
            f'{MAGIC_STRING_LEN}sHQd' ,
            response[:self.all_header_size]
        )
        if magic_string == MAGIC_STRING:
          return Pong(connection_id, icmp_seq, timestamp, now-timestamp, source_addr, ttl)
        else:
          print('.', end='', flush=True)
          return None
    except socket.error as error:
      #TODO: this is probably fatal. Shut down gracefully. Though I've only ever seen it when ^C.
      print(f'Erorr: {error}')


class QueueManager():
  def __init__(self, socket_manager):
    self.queue = PriorityQueue()
    self.targets = {}
    self.queue_lock = threading.Lock()
    self.socket_manager = socket_manager
    self.events = defaultdict(Queue)

    self.receiver_thread = threading.Thread(target=self.receiver)
    self.sender_thread = threading.Thread(target=self.sender)

    self.receiver_thread.start()
    self.sender_thread.start()

  def receiver(self):
    print('receiver running...')
    while True:
      pong = self.socket_manager.tick(1)
      if pong:
        # For some reason, tick is occasionally rejecting
        self.events[pong.connection_id].put(pong)

  def sender(self):
    print('sender running...')
    while True:
      while self.queue.empty():
        #TODO: make this block on a locking gate that is released by add_target
        time.sleep(1)

      with self.queue_lock:
        _, next_target = self.queue.get()

      #TODO: replace this with something that can be interrupted by add_target:
      sleep_time = next_target.next_ping_time - time.time()
      if sleep_time > 0:
        time.sleep(sleep_time)

      ping = None
      try:
        #TODO: deal with the race condition: Can a target still be queued after requestor has killed it?
        ping = self.socket_manager.send(
            next_target.resolved_address, next_target.connection_id,
            next_target.icmp_seq, next_target.packet_size)
      except OSError as e:
        # "Network is Unreachable". If that's the case, report that the packet was sent. This isn't
        # true, of course, but the way a user will experience it is as an inability to traverse the
        # network.
        ping = Ping(next_target.resolved_address, next_target.connection_id, next_target.icmp_seq,
                    time.time())

      self.events[next_target.connection_id].put(ping)
      next_target.bump()
      # There's a chance that this target has been removed since we pulled it from the queue, so
      # we need to see if it still exists before we requeue it.
      if next_target.connection_id in self.targets:
        with self.queue_lock:
          self.queue.put((next_target.next_ping_time, next_target))

  def get_event(self, connection_id):
    return self.events[connection_id].get()

  def add_target(self, address='8.8.8.8', resolved_address='8.8.8.8', packet_size=64, interval=1.0,
                 connection_id=-1):
    print('add_target called w/ interval=', interval)
    target = Target(address, resolved_address, connection_id, packet_size, interval)
    next_ping_time = time.time() + 0.01
    target.next_ping_time = next_ping_time
    with self.queue_lock:
      self.targets[connection_id] = target
      self.queue.put((next_ping_time, target))

  def remove_target(self, connection_id):
    #I can't just store a connection_id and ignore it when I come across it - that connection_id may be reused.
    #TODO: is there a better way?
    removed_targets = []
    with self.queue_lock:
      new_pq = PriorityQueue()
      while(len(self.queue.queue)):
        prio, target = self.queue.get()
        if target.connection_id == connection_id:
          removed_targets.append(target)
        else:
          new_pq.put((prio, target))
      self.queue = new_pq

      new_targets = {}
      for k,v in self.targets.items():
        if k != connection_id:
          new_targets[k] = v
      self.targets = new_targets
    return removed_targets


SOCKET_PATH = '/tmp/user_icmp_socket'
if os.path.exists(SOCKET_PATH):
  os.remove(SOCKET_PATH)

socket_manager = SocketManager()
queue_manager = QueueManager(socket_manager)

next_unique_id = -1
def get_next_unique_id():
  global next_unique_id

  next_unique_id += 1
  return next_unique_id


class RequestHandler(BaseHTTPRequestHandler):
  def encode_as_wire_message(self, data):
    return bytes('data: ' + str(data) + '\n\n', 'utf8')

  def do_GET(self):
    parsed_url = urlparse(self.path)
    query_params = parse_qs(parsed_url.query)

    for k,v in query_params.items():
      query_params[k] = v[0]

    #TODO: ensure that the request comes from localhost. Figure out who the user
    #      is and log the request. Also, occasionally log their usage and when
    #      they disconnect, log a summary.

    endpoint = {
      'address': '8.8.8.8',
      'interval': '1.0',
      'packet_size': '64',
    }

    endpoint.update(query_params)
    keys = list(endpoint.keys())
    keys.sort()

    if keys != ['address', 'interval', 'packet_size']:
      self.send_response(404)
      self.end_headers()
      self.finish()
      self.connection.close()
      return

    endpoint['interval'] = float(endpoint['interval'])
    endpoint['packet_size'] = int(endpoint['packet_size'])
    endpoint['resolved_address'] = socket.gethostbyname(endpoint['address'])
    endpoint['connection_id'] = get_next_unique_id()
    print('endpoint created:', endpoint)
    queue_manager.add_target(**endpoint)

    self.send_response(200)
    self.send_header('Content-type', 'text/event-stream')
    self.send_header('Cache-Control', 'no-cache')
    self.send_header('Connection', 'keep-alive')
    self.send_header('Access-Control-Allow-Credentials', 'true')
    self.send_header('Access-Control-Allow-Origin', '*')
    self.end_headers()

    while True:
      event = queue_manager.get_event(endpoint['connection_id'])
      wire_message = self.encode_as_wire_message(str(event))
      self.wfile.write(wire_message)

# UNDER NO CIRCUMSTANCES WILL THIS SURVIVE PAST THE PROTOTYPE PHASE. I don't
# trust the python httpd to serve traffic as root. When this gets ported to C,
# it'll be a bespoke solution to serve ONLY very simple HTTP.
def serve_requests(server_class=ThreadingHTTPServer, handler_class=RequestHandler):
  #TODO: make port user-configurable
  server_address = ('', 8000)
  httpd = server_class(server_address, handler_class)
  
  print('starting httpd...')
  httpd.serve_forever()


serve_requests()
print('after server_requests')


