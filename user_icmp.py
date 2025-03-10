#!/usr/bin/env python3

# TODO:
# * Should I stop sending fileno over the network? Writting a mapper just adds
#   more code that has to run in privileged mode.
# * need to consider defense against abusers. I have a brief delay before
#   sending starts, but I should keep a token bucket for each user and allow
#   admin to set the refil rate and count.
# * Do I need a defense against bursting? If 100 targets are added at the same
#   time with the same interval, they're going to tend to affect each other.
# * Track the number of times bump() has been called since a target was created.
#   Slightly alter the ACTUAL amount we bump by to try to meet the average?
# * SHould it be left to the user to determine RTT? If so, I can save 8 bytes.
# * need to chroot jail the process
# * handle Destination Net Unreachable.

from collections import defaultdict
import os
from queue import PriorityQueue, Queue
import random
import re
import socket
import struct
import threading
import time

MAX_PACKET_SIZE = 8192
MAGIC_STRING = bytes('867-5309', 'utf-8')
MAGIC_STRING_LEN = len(MAGIC_STRING)

#TODO: make Ping and Pong derive from a common ancestor

class ICMP():
  def to_dotted_ip(self, long):
    return f'{(long>>24) % 256}.{(long>>16) % 256}.{(long>>8) % 256}.{(long) % 256}'

  def to_bytes(self):
    return(bytes(self.str(), 'utf-8'))

class Ping(ICMP):
  def __init__(self, fileno, icmp_seq, timestamp):
    self.fileno = fileno
    self.icmp_seq = icmp_seq
    self.timestamp = timestamp

  def str(self):
    return f'S {self.fileno} {self.icmp_seq} {self.timestamp}\n'

class Pong(ICMP):
  def __init__(self, fileno, icmp_seq, timestamp, rtt, source_ip, ttl):
    self.fileno = fileno
    self.icmp_seq = icmp_seq
    self.timestamp = timestamp
    self.rtt = rtt
    self.source_ip = source_ip
    self.ttl = ttl

  def str(self):
    dotted_ip = self.to_dotted_ip(self.source_ip)
    return f'R {self.fileno} {self.icmp_seq} {self.timestamp} {self.rtt} {dotted_ip} {self.ttl}\n'

#TODO: derive a Target type for handling traceroutes
class Target():
  def __init__(self, unresolved_address, resolved_address, fileno, min_packet_size, interval):
    self.unresolved_address = unresolved_address
    self.resolved_address = resolved_address
    self.fileno = fileno
    self.min_packet_size = min_packet_size
    self.interval = interval
    self.icmp_seq = 1

  def __str__(self):
    return f'{self.unresolved_address} {self.resolved_address} fd:{self.fileno}'

  def bump(self):
    self.next_ping_time += self.interval
    self.icmp_seq += 1

class SocketManager():
  def __init__(self):
    self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    self.ip_header_size = 20
    self.icmp_header_size = 8
    # magic, fileno, icmp_seq, timestamp
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

  def build_icmp(self, payload, fileno, icmp_seq):
    now = time.time()
    icmp_packet = (struct.pack(
        f'!BBHHH{MAGIC_STRING_LEN}sHQd',
        #type, code, checksum, identifier, seq number
        8, 0, 0, 12345, icmp_seq % 65536,
        MAGIC_STRING, fileno, icmp_seq, now)
        + payload
    )
    c = self.calc_checksum(icmp_packet)
    icmp_packet = (struct.pack(
        f'!BBHHH{MAGIC_STRING_LEN}sHQd',
        #type, code, checksum, identifier, seq number
        8, 0, c, 12345, icmp_seq % 65536,
        MAGIC_STRING, fileno, icmp_seq, now)
        + payload
    )

    return icmp_packet, now

  #TODO: if "destination" is an ip name with multiple associated ip addresses (like amazon.com),
  #      sendto will arbitrarily choose between them with each packet. Kinda need to fix this.
  def send(self, destination, fileno, icmp_seq, length):
    # TODO: don't build the pad every time. Stash it in the target or something.
    payload = bytes('x', 'utf-8') * (length - self.icmp_header_size - self.user_ping_header_size)
    packet, timestamp = self.build_icmp(payload, fileno, icmp_seq)
    self.raw_socket.sendto(packet, (destination, 0))

    return Ping(fileno, icmp_seq, timestamp)

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
            magic_string, fileno, icmp_seq, timestamp
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
          return Pong(fileno, icmp_seq, timestamp, now-timestamp, source_addr, ttl)
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
        self.events[pong.fileno].put(pong)

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

      #TODO: deal with the race condition: Can a target still be queued after requestor has killed it?
      ping = self.socket_manager.send(
          next_target.resolved_address, next_target.fileno,
          next_target.icmp_seq, next_target.min_packet_size)

      self.events[next_target.fileno].put(ping)
      next_target.bump()
      # There's a chance that this target has been removed since we pulled it from the queue, so
      # we need to see if it still exists before we requeue it.
      if next_target.fileno in self.targets:
        with self.queue_lock:
          self.queue.put((next_target.next_ping_time, next_target))

  def get_event(self, fileno):
    return self.events[fileno].get()

  def add_target(self, unresolved_address, resolved_address, fileno, min_packet_size, interval):
    target = Target(unresolved_address, resolved_address, fileno, min_packet_size, interval)
    next_ping_time = time.time() + 0.01
    target.next_ping_time = next_ping_time
    with self.queue_lock:
      self.targets[fileno] = target
      self.queue.put((next_ping_time, target))

  def remove_target(self, fileno):
    #I can't just store a fileno and ignore it when I come across it - that fileno may be reused.
    #TODO: is there a better way?
    removed_targets = []
    with self.queue_lock:
      new_pq = PriorityQueue()
      while(len(self.queue.queue)):
        prio, target = self.queue.get()
        if target.fileno == fileno:
          removed_targets.append(target)
        else:
          new_pq.put((prio, target))
      self.queue = new_pq

      new_targets = {}
      for k,v in self.targets.items():
        if k != fileno:
          new_targets[k] = v
      self.targets = new_targets
    return removed_targets

SOCKET_PATH = '/tmp/user_icmp_socket'
if os.path.exists(SOCKET_PATH):
  os.remove(SOCKET_PATH)

#TODO: log requests, especially abuses (like interval less than 0.005)
def get_client_uid(connection):
  try:
    fmt = 'i i i'
    ucred = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize(fmt))
    pid, uid, gid = struct.unpack(fmt, ucred)
    return uid
  except OSError as e:
    print(f'Error getting client credentials: {e}')
    return None

class ClientHandler():
  #TODO: unicode characters. Limit interval to one decimal point.
  ping_start_command_re = r'^P [a-zA-Z0-9.-]+ [0-9.]+ [0-9]+$'

  def __init__(self):
    self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.server_socket.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o777)
    self.server_socket.listen(1) #TODO: does the backlog (currently 1) need to be increased?

    self.socket_manager = SocketManager()
    self.queue_manager = QueueManager(self.socket_manager)

  def handle_command(self, connection):
    try:
      command = connection.recv(8192)
      if(len(command) < 5 or len(command) > 8180):
        #client has disconnected, or they're sending something weird and we're hanging up.
        return False
    except TimeoutError as to:
      return True

    command = command.decode()
    if not re.match(ClientHandler.ping_start_command_re, command):
      return False

    _, unresolved_address, interval, size = command.split()
    interval = max(float(interval), 0.01)
    size = min(int(size), 8192)
    try:
      resolved_address = socket.gethostbyname(unresolved_address)
      self.queue_manager.add_target(
          unresolved_address, resolved_address, connection.fileno(), size, interval)
    except socket.gaierror as e:
      connection.sendall(bytes(f'E {unresolved_address} {e}\n'))
      return False

    return True

  def handle_client_connection(self, connection):
    try:
      if not self.handle_command(connection):
        return

      while True:
        #check for messages, pass them to the user:
        event = self.queue_manager.get_event(connection.fileno())
        if not event:
          return
        connection.sendall(event.to_bytes())

    except BrokenPipeError as e:
      print(f'BrokenPipeError (probably, user closed connection) on fileno {connection.fileno()}')
      pass
    finally:
      victims = self.queue_manager.remove_target(connection.fileno())
      print(f'closing connection for fileno {connection.fileno()}...')
      connection.close()

  def run(self):
    try:
      while True:
        connection, _ = self.server_socket.accept()
        uid = get_client_uid(connection)
        print(f'new connection from user {uid}, fileno: {connection.fileno()}')
        t = threading.Thread(target=self.handle_client_connection, args=(connection,))
        t.start()

    finally:
      print('closing socket...')
      self.server_socket.close()
      print('socket closed')
      #os.remove(SOCKET_PATH)
      print('socket path removed')

client_handler = ClientHandler()
client_handler.run()
