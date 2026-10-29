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
//   |    fudge    |                   2 bytes that pin the checksum (flows)
//   +-------------+-------------+
//   | 'x' padding ...           |   up to packet_size total
//   +---------------------------+
//
// Probes for route discovery are the same packets sent with a small TTL. A
// router that drops one for running out of TTL sends back ICMP Time
// Exceeded, quoting our IP header and (at least) the 8 ICMP header bytes
// above - which is all we need to know which probe it was.
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

// The smallest ICMP message we will build: 8-byte header + 8-byte magic +
// 2 fudge bytes.
const int MIN_PACKET_SIZE = 18;
// The largest. Anything above the path MTU gets fragmented, which is legal but
// rarely what anyone wants to measure.
const int MAX_PACKET_SIZE = 8192;

// Something that arrived on the raw socket that concerns one of OUR echo
// requests: either the echo reply itself, or an ICMP error a router sent back
// about it (Time Exceeded for a TTL-limited probe, Destination Unreachable,
// ...). Either way, identifier and sequence identify which of our packets it
// was about.
enum IcmpMessageKind {
  ICMP_ECHO_REPLY,
  ICMP_ERROR
};

struct IcmpMessage {
  IcmpMessageKind kind;
  struct in_addr source;   // who sent this message (the target, or a router)
  uint16_t identifier;     // of OUR packet
  uint16_t sequence;       // of OUR packet
  int ttl;                 // TTL of this message as it arrived
  int error_type;          // ICMP_ERROR only: 3 = unreachable, 11 = time exceeded, ...
  int error_code;          // ICMP_ERROR only
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
  //
  // fixed_checksum: -1 lets the checksum fall where it may. 0..65535 forces
  // the ICMP checksum to that exact value (using the fudge bytes), which is
  // what makes a "flow": per-flow load balancers hash on the checksum, so
  // every packet with the same checksum takes the same path. Avoid 0x0000
  // and 0xffff, which are the same number in ones-complement arithmetic.
  //
  // ttl: the IP time-to-live to send with; 0 means the system default.
  int send_echo(const struct in_addr& destination, uint16_t identifier,
                uint16_t sequence, int packet_size, int fixed_checksum, int ttl);

  // Non-blocking. Returns true and fills *message if an echo reply, or an
  // ICMP error quoting one of our echo requests, was waiting; returns false
  // when there was nothing (more) of interest. Packets that are not ours are
  // silently consumed, so callers should keep calling until is_drained().
  // Whether a message is really ours is finally decided by the caller,
  // which looks up (identifier, sequence) in its table of outstanding
  // packets.
  bool receive_message(IcmpMessage* message);

  // True if the last receive_message() returned false because the socket is
  // drained (EAGAIN), false if it consumed an uninteresting packet and there
  // may be more. Lets the caller loop "until drained".
  bool is_drained() const;

private:
  static uint16_t checksum(const unsigned char* data, int length);

  int fd;
  bool drained;
  int current_ttl;         // what IP_TTL is set to now (0 = never set)
  unsigned char send_buffer[MAX_PACKET_SIZE];
  unsigned char receive_buffer[MAX_PACKET_SIZE + 1024];
};

#endif
