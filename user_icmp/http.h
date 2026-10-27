// http.h - the very small slice of HTTP the daemon speaks.
//
// The browser can't open raw sockets or Unix domain sockets, so it reaches us
// with an EventSource (Server-Sent Events): one GET request, after which the
// response body is an endless stream of
//
//     data: {...json...}\n\n
//
// records. That's ALL we implement:
//   * read one request head (up to the blank line), GET only, no body
//   * reply with an error status, or with SSE headers followed by events
//
// No keep-alive, chunking, pipelining, or anything else. The parser is
// intentionally strict and small because it's exposed to (local) input.
//
// The browser-facing protocol is unchanged from user_icmp2.py:
//
//     GET /?address=<name or a.b.c.d>&interval=<seconds>&packet_size=<bytes>
//
// All three parameters are optional (defaults: 8.8.8.8, 1.0, 64). Any other
// parameter is rejected.

#ifndef USER_ICMP_HTTP_H
#define USER_ICMP_HTTP_H

#include <map>
#include <stdint.h>
#include <string>

// The longest request head we'll accept before giving up on a client.
const size_t MAX_REQUEST_HEAD = 8192;

struct HttpRequest {
  std::string method;
  std::string path;                               // without the query string
  std::map<std::string, std::string> query;       // decoded
};

// Returns the offset just past the "\r\n\r\n" that ends the request head, or
// 0 if the head isn't complete yet.
size_t find_end_of_head(const std::string& buffer);

// Parses the request line of a complete head. Returns false if malformed.
bool parse_request(const std::string& head, HttpRequest* request);

std::string make_error_response(int status, const std::string& reason, const std::string& body);
std::string make_event_stream_headers();

// SSE records. Field names and meanings match what pingem.html expects.
//   ping:  {"type":"ping","to":"a.b.c.d","icmp_seq":N,"timestamp":T}
//          T = wall-clock time the packet was handed to the kernel. Also sent
//          (with the same T) when sendto() failed, e.g. network unreachable:
//          the user should see that as loss, not as a gap.
//   reply: {"type":"reply","from":"a.b.c.d","icmp_seq":N,"timestamp":T,"rtt":R,"ttl":L}
//          T = wall-clock time the reply was received; R in seconds.
std::string make_ping_event(const std::string& to, uint64_t icmp_seq, double timestamp);
std::string make_reply_event(const std::string& from, uint64_t icmp_seq, double timestamp,
                             double rtt, int ttl);

#endif
