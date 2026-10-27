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
static const int ICMP_HEADER_LENGTH = 8;
static const uint8_t ICMP_TYPE_ECHO_REPLY = 0;
static const uint8_t ICMP_TYPE_ECHO_REQUEST = 8;

IcmpSocket::IcmpSocket() : fd(-1), drained(true) {
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
  // types to *block*. For now we only want echo replies; Time Exceeded (11)
  // and Destination Unreachable (3) get unblocked when route probing lands.
  struct icmp_filter filter;
  filter.data = ~(1U << ICMP_TYPE_ECHO_REPLY);
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

int IcmpSocket::send_echo(const struct in_addr& destination, uint16_t identifier,
                          uint16_t sequence, int packet_size) {
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
  memset(p + ICMP_HEADER_LENGTH + MAGIC_LENGTH, 'x',
         packet_size - ICMP_HEADER_LENGTH - MAGIC_LENGTH);

  uint16_t sum = checksum(p, packet_size);
  p[2] = (unsigned char)(sum >> 8);
  p[3] = (unsigned char)(sum & 0xff);

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

bool IcmpSocket::receive_echo_reply(EchoReply* reply) {
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
  // (IHL field, in 32-bit words) - the old Python assumed 20 bytes.
  if (length < 20) {
    return false;
  }
  const struct iphdr* ip = (const struct iphdr*)receive_buffer;
  int ip_header_length = ip->ihl * 4;
  if (ip_header_length < 20 || length < ip_header_length + ICMP_HEADER_LENGTH + MAGIC_LENGTH) {
    return false;
  }

  const unsigned char* icmp = receive_buffer + ip_header_length;
  if (icmp[0] != ICMP_TYPE_ECHO_REPLY || icmp[1] != 0) {
    return false;
  }
  if (memcmp(icmp + ICMP_HEADER_LENGTH, MAGIC, MAGIC_LENGTH) != 0) {
    return false;  // somebody else's ping (e.g. /usr/bin/ping) - not ours
  }

  reply->source.s_addr = ip->saddr;
  reply->identifier = (uint16_t)((icmp[4] << 8) | icmp[5]);
  reply->sequence = (uint16_t)((icmp[6] << 8) | icmp[7]);
  reply->ttl = ip->ttl;
  reply->receive_monotonic = now_monotonic;
  reply->receive_realtime = now_realtime;
  return true;
}
