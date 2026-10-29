#include "icmp_socket.h"

#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/icmp.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char MAGIC[] = "867-5309";
static const int MAGIC_LENGTH = 8;
// Two payload bytes, right after the magic, adjusted so the ICMP checksum
// comes out to a chosen value. See send_echo().
static const int FUDGE_OFFSET = 8 + MAGIC_LENGTH;   // 16-bit aligned
static const int FUDGE_LENGTH = 2;
static const int ICMP_HEADER_LENGTH = 8;
static const uint8_t ICMP_TYPE_ECHO_REPLY = 0;
static const uint8_t ICMP_TYPE_ECHO_REQUEST = 8;
static const uint8_t ICMP_TYPE_DESTINATION_UNREACHABLE = 3;
static const uint8_t ICMP_TYPE_TIME_EXCEEDED = 11;

IcmpSocket::IcmpSocket() : fd(-1), drained(true), current_ttl(0) {
}

IcmpSocket::~IcmpSocket() {
  if (fd >= 0) {
    close(fd);
  }
}

bool IcmpSocket::open_socket() {
  fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
  if (fd < 0) {
    return false;
  }

  // Every raw ICMP socket on Linux receives a copy of EVERY incoming ICMP
  // packet on the machine. ICMP_FILTER lets the kernel discard the types we
  // don't care about before they're copied to us. The filter is a bitmask of
  // types to *block*. We want echo replies, plus the two errors that can
  // come back about our echo requests: Destination Unreachable and Time
  // Exceeded (the answer to a TTL-limited probe).
  struct icmp_filter filter;
  filter.data = ~((1U << ICMP_TYPE_ECHO_REPLY) | (1U << ICMP_TYPE_DESTINATION_UNREACHABLE) |
                  (1U << ICMP_TYPE_TIME_EXCEEDED));
  if (setsockopt(fd, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter)) < 0) {
    log_message("warning: ICMP_FILTER failed (%s); continuing unfiltered", strerror(errno));
  }

  // A larger receive buffer means a burst of replies (or a stall in our loop)
  // doesn't turn into drops in the kernel, which would look like packet loss.
  int buffer_size = 1024 * 1024;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
  return true;
}

int IcmpSocket::get_fd() const {
  return fd;
}

// The standard Internet checksum (RFC 1071): the ones-complement of the
// ones-complement sum of the data taken as 16-bit big-endian words.
uint16_t IcmpSocket::checksum(const unsigned char* data, int length) {
  uint32_t sum = 0;
  int i = 0;
  for (; i + 1 < length; i += 2) {
    sum += ((uint32_t)data[i] << 8) | data[i + 1];
  }
  if (i < length) {
    sum += (uint32_t)data[i] << 8;  // odd trailing byte, padded with zero
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (uint16_t)(~sum & 0xffff);
}

// Ones-complement addition of two 16-bit values, with end-around carry.
static uint16_t ones_add(uint16_t a, uint16_t b) {
  uint32_t sum = (uint32_t)a + (uint32_t)b;
  sum = (sum & 0xffff) + (sum >> 16);
  return (uint16_t)sum;
}

int IcmpSocket::send_echo(const struct in_addr& destination, uint16_t identifier,
                          uint16_t sequence, int packet_size, int fixed_checksum,
                          int ttl) {
  if (packet_size < MIN_PACKET_SIZE) {
    packet_size = MIN_PACKET_SIZE;
  }
  if (packet_size > MAX_PACKET_SIZE) {
    packet_size = MAX_PACKET_SIZE;
  }

  unsigned char* p = send_buffer;
  p[0] = ICMP_TYPE_ECHO_REQUEST;
  p[1] = 0;            // code
  p[2] = 0;            // checksum, filled in below
  p[3] = 0;
  p[4] = (unsigned char)(identifier >> 8);
  p[5] = (unsigned char)(identifier & 0xff);
  p[6] = (unsigned char)(sequence >> 8);
  p[7] = (unsigned char)(sequence & 0xff);
  memcpy(p + ICMP_HEADER_LENGTH, MAGIC, MAGIC_LENGTH);
  p[FUDGE_OFFSET] = 0;
  p[FUDGE_OFFSET + 1] = 0;
  memset(p + FUDGE_OFFSET + FUDGE_LENGTH, 'x', packet_size - FUDGE_OFFSET - FUDGE_LENGTH);

  if (fixed_checksum < 0) {
    // Free checksum: whatever the contents add up to. It changes with every
    // sequence number, so load balancers may scatter these packets across
    // parallel paths.
    uint16_t sum = checksum(p, packet_size);
    p[2] = (unsigned char)(sum >> 8);
    p[3] = (unsigned char)(sum & 0xff);
  } else {
    // Fixed checksum (Paris traceroute's trick, but done in the payload so the
    // identifier and sequence number stay free). The receiver's check is
    // that all 16-bit words of the message, including the checksum field,
    // add up (ones-complement) to 0xffff. With the checksum field set to T
    // and the fudge word F still zero, the other words sum to S. So choose
    //     F = ~(S + T)
    // and S + T + F = 0xffff: the packet is valid AND its checksum is T, no
    // matter what the identifier and sequence number are.
    uint16_t target = (uint16_t)fixed_checksum;
    uint16_t sum_of_rest = (uint16_t)~checksum(p, packet_size);   // S
    uint16_t fudge = (uint16_t)~ones_add(sum_of_rest, target);
    p[2] = (unsigned char)(target >> 8);
    p[3] = (unsigned char)(target & 0xff);
    p[FUDGE_OFFSET] = (unsigned char)(fudge >> 8);
    p[FUDGE_OFFSET + 1] = (unsigned char)(fudge & 0xff);
  }

  // TTL is a socket option, so it's set per send - but only when it changes,
  // since pings (default TTL) and probes (small TTLs) interleave.
  int wanted_ttl = (ttl > 0) ? ttl : 64;
  if (wanted_ttl != current_ttl) {
    if (setsockopt(fd, IPPROTO_IP, IP_TTL, &wanted_ttl, sizeof(wanted_ttl)) == 0) {
      current_ttl = wanted_ttl;
    }
  }

  struct sockaddr_in to;
  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_addr = destination;

  ssize_t sent = sendto(fd, p, packet_size, 0, (struct sockaddr*)&to, sizeof(to));
  if (sent < 0) {
    return errno;
  }
  return 0;
}

bool IcmpSocket::is_drained() const {
  return drained;
}

// Reads one packet. The interesting cases:
//
//   Echo reply:   [IP header][ICMP type 0, id, seq][magic ...]
//   ICMP error:   [IP header][ICMP type 3 or 11, code][4 unused bytes]
//                 [the IP header of OUR packet][first 8+ bytes of OUR ICMP]
//
// For an error, the router quotes back the start of the packet that caused
// it. RFC 792 only guarantees 8 bytes past the quoted IP header - exactly our
// ICMP header, with the identifier and sequence number - so that's all we
// use. The magic string usually isn't quoted, so errors are matched purely
// by (identifier, sequence) in the caller's packet table.
bool IcmpSocket::receive_message(IcmpMessage* message) {
  drained = false;
  ssize_t length = recv(fd, receive_buffer, sizeof(receive_buffer), 0);
  // Take the timestamps immediately, before any parsing.
  double now_monotonic = monotonic_now();
  double now_realtime = realtime_now();

  if (length < 0) {
    // EAGAIN means "nothing to read". Anything else is unexpected, but there
    // is nothing useful to do with it except report it and stop reading.
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      log_message("recv on raw socket failed: %s", strerror(errno));
    }
    drained = true;
    return false;
  }

  // A raw IPv4 socket hands us the IP header too. Its length is variable
  // (IHL field, in 32-bit words).
  if (length < 20) {
    return false;
  }
  const struct iphdr* ip = (const struct iphdr*)receive_buffer;
  int ip_header_length = ip->ihl * 4;
  if (ip_header_length < 20 || length < ip_header_length + ICMP_HEADER_LENGTH) {
    return false;
  }
  const unsigned char* icmp = receive_buffer + ip_header_length;
  int icmp_length = (int)length - ip_header_length;

  message->source.s_addr = ip->saddr;
  message->ttl = ip->ttl;
  message->receive_monotonic = now_monotonic;
  message->receive_realtime = now_realtime;

  if (icmp[0] == ICMP_TYPE_ECHO_REPLY) {
    if (icmp[1] != 0 || icmp_length < ICMP_HEADER_LENGTH + MAGIC_LENGTH ||
        memcmp(icmp + ICMP_HEADER_LENGTH, MAGIC, MAGIC_LENGTH) != 0) {
      return false;  // somebody else's ping (e.g. /usr/bin/ping) - not ours
    }
    message->kind = ICMP_ECHO_REPLY;
    message->identifier = (uint16_t)((icmp[4] << 8) | icmp[5]);
    message->sequence = (uint16_t)((icmp[6] << 8) | icmp[7]);
    message->error_type = 0;
    message->error_code = 0;
    return true;
  }

  if (icmp[0] != ICMP_TYPE_DESTINATION_UNREACHABLE && icmp[0] != ICMP_TYPE_TIME_EXCEEDED) {
    return false;
  }
  // The quoted packet starts after the 8-byte error header.
  const unsigned char* quoted = icmp + ICMP_HEADER_LENGTH;
  int quoted_length = icmp_length - ICMP_HEADER_LENGTH;
  if (quoted_length < 20) {
    return false;
  }
  const struct iphdr* quoted_ip = (const struct iphdr*)quoted;
  int quoted_ip_header_length = quoted_ip->ihl * 4;
  if (quoted_ip_header_length < 20 || quoted_ip->protocol != IPPROTO_ICMP ||
      quoted_length < quoted_ip_header_length + ICMP_HEADER_LENGTH) {
    return false;
  }
  const unsigned char* quoted_icmp = quoted + quoted_ip_header_length;
  if (quoted_icmp[0] != ICMP_TYPE_ECHO_REQUEST) {
    return false;  // an error about something other than a ping
  }
  message->kind = ICMP_ERROR;
  message->error_type = icmp[0];
  message->error_code = icmp[1];
  message->identifier = (uint16_t)((quoted_icmp[4] << 8) | quoted_icmp[5]);
  message->sequence = (uint16_t)((quoted_icmp[6] << 8) | quoted_icmp[7]);
  return true;
}
