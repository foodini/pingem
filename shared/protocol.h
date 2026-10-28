// protocol.h - the line protocol spoken between user_icmp and its clients over
// the Unix domain socket. Used by BOTH sides, so this file is the definition
// of the protocol.
//
// Transport: a SOCK_STREAM Unix socket in the Linux abstract namespace, named
// "@user_icmp" by default (no file on disk; see USER_ICMP_SOCKET_NAME).
//
// Format: one message per line, '\n' terminated, plain ASCII so a human can
// drive it with socat:
//
//     socat - ABSTRACT-CONNECT:user_icmp
//
// A message is a verb, then positional arguments, then key=value fields, all
// separated by single spaces. Values never contain spaces.
//
// Client -> daemon:
//     add <id> <host> [interval=<seconds>] [size=<bytes>] [flows=<K>]
//         Start pinging <host>. <id> is a non-negative integer the CLIENT
//         chooses; every event about this target carries it. Defaults:
//         interval=1 size=64 flows=0.
//
//         flows=K (1..64) spreads the pings over K "flows". Every packet in a
//         flow has the same ICMP checksum, so routers that load-balance by
//         hashing header fields send the whole flow down the same path.
//         Ping n (counting from 1) belongs to flow (n-1) mod K. flows=0 (the
//         default) leaves the checksum free to vary, as plain ping does.
//     remove <id>
//
// Daemon -> client:
//     hello user_icmp <version>
//         Sent once, on connect.
//     added <id> <host> <address>
//         <host> resolved to <address>; pings start shortly.
//     removed <id>
//     error <id> <message...>
//         <id> is "-" when the error isn't about a target. The message is
//         free text and is the only place spaces are allowed.
//     ping <id> seq=<n> t=<send time> [flow=<f>]
//     reply <id> seq=<n> t=<receive time> rtt=<seconds> ttl=<ttl> from=<address> [flow=<f>]
//         Times are wall-clock seconds since the epoch. seq starts at 1 for
//         each target and increments by one per packet. flow= is present
//         only for targets added with flows=K, and is 0..K-1.

#ifndef PINGEM_SHARED_PROTOCOL_H
#define PINGEM_SHARED_PROTOCOL_H

#include <map>
#include <stdint.h>
#include <string>
#include <vector>

const int PROTOCOL_VERSION = 1;
const int MAX_FLOWS = 64;
const char* const USER_ICMP_SOCKET_NAME = "user_icmp";   // abstract: "@user_icmp"

// Lines longer than this are a protocol error.
const size_t MAX_LINE_LENGTH = 1024;

// Accumulates bytes from a stream socket and hands back complete lines.
class LineBuffer {
public:
  void append(const char* data, size_t length);

  // Removes the next complete line (without its '\n', and without a trailing
  // '\r' if present) and returns true; returns false if no complete line is
  // buffered yet.
  bool next_line(std::string* line);

  // True if the buffer holds a partial line longer than MAX_LINE_LENGTH -
  // the peer is misbehaving.
  bool overflowed() const;

private:
  std::string buffer;
};

struct Message {
  std::string verb;
  std::vector<std::string> args;               // positional, in order
  std::map<std::string, std::string> fields;   // key=value
  std::string text;                            // the rest of an "error" line
};

// Splits a line into a Message. Returns false on an empty line.
bool parse_message(const std::string& line, Message* message);

// Field accessors. They return false if the field is missing or malformed.
bool get_field(const Message& message, const std::string& key, double* value);
bool get_field(const Message& message, const std::string& key, uint64_t* value);
bool get_field(const Message& message, const std::string& key, int* value);
bool get_field(const Message& message, const std::string& key, std::string* value);

// Parses a whole string as a non-negative integer id.
bool parse_id(const std::string& text, int* id);

// Formatting. Each returns a complete line including the '\n'.
std::string format_hello();
std::string format_add(int id, const std::string& host, double interval, int size, int flows);
std::string format_remove(int id);
std::string format_added(int id, const std::string& host, const std::string& address);
std::string format_removed(int id);
std::string format_error(int id, const std::string& text);   // id < 0 prints "-"
// flow < 0 omits the flow= field.
std::string format_ping(int id, uint64_t seq, double send_time, int flow);
std::string format_reply(int id, uint64_t seq, double receive_time, double rtt, int ttl,
                         const std::string& from, int flow);

#endif
