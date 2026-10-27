// icmp_socket.h - the raw ICMP socket: building and sending echo requests,
// receiving and decoding echo replies.
//
// This is the only part of the daemon that needs privilege. The socket is
// opened while we are still root; main() then drops to an unprivileged user and
// the already-open descriptor keeps working.
//
// What goes on the wire (ICMP message, after the 20+ byte IP header the kernel
// adds for us):
//
//    0      1      2      3
//   +------+------+------+------+
//   | type | code |  checksum   |   type=8 (echo request), code=0
//   +------+------+------+------+
//   |  identifier |  sequence   |   both 16 bits, see below
//   +------+------+------+------+
//   | "867-5309" (8 bytes)      |   magic, only a cheap sanity filter
//   +---------------------------+
//   | 'x' padding ...           |   up to packet_size total
//   +---------------------------+
//
// The identifier and sequence number are the ONLY fields we rely on to match a
// reply (or, later, a Time Exceeded) to the packet that caused it. Those 8
// header bytes are the part of our packet that every router is required to
// quote back (RFC 792), so a truncated payload can never cost us data. The
// full 64-bit sequence number and the send time live in the daemon's
// PacketTable, keyed by (identifier, sequence).

#ifndef USER_ICMP_ICMP_SOCKET_H
#define USER_ICMP_ICMP_SOCKET_H

#include <netinet/in.h>
#include <stdint.h>

// The smallest ICMP message we will build: 8-byte header + 8-byte magic.
const int MIN_PACKET_SIZE = 16;
// The largest. Anything above the path MTU gets fragmented, which is legal but
// rarely what anyone wants to measure.
const int MAX_PACKET_SIZE = 8192;

struct EchoReply {
  struct in_addr source;   // who answered
  uint16_t identifier;
  uint16_t sequence;
  int ttl;                 // TTL of the reply as it arrived
  double receive_monotonic;
  double receive_realtime;
};

class IcmpSocket {
public:
  IcmpSocket();
  ~IcmpSocket();

  // Opens the raw socket. Returns false (with errno set) on failure - almost
  // always because we are neither root nor holding CAP_NET_RAW.
  bool open_socket();
  int get_fd() const;

  // Sends one echo request. Returns 0 on success, otherwise the errno from
  // sendto() (e.g. ENETUNREACH when the network is down).
  int send_echo(const struct in_addr& destination, uint16_t identifier,
                uint16_t sequence, int packet_size);

  // Non-blocking. Returns true and fills *reply if an echo reply with our
  // magic was waiting; returns false when there is nothing (more) to read.
  // Packets that are not ours are silently consumed, so callers should keep
  // calling until it returns false.
  bool receive_echo_reply(EchoReply* reply);

  // True if the last receive_echo_reply() returned false because the socket
  // is drained (EAGAIN), false if it consumed an uninteresting packet and
  // there may be more. Lets the caller loop "until drained".
  bool is_drained() const;

private:
  static uint16_t checksum(const unsigned char* data, int length);

  int fd;
  bool drained;
  unsigned char send_buffer[MAX_PACKET_SIZE];
  unsigned char receive_buffer[MAX_PACKET_SIZE + 1024];
};

#endif
