// daemon_link.h - the client's connection to user_icmp over its Unix socket.
//
// Polled, like everything else: once per frame the main loop calls poll(),
// which (re)connects if needed, sends anything queued, reads whatever has
// arrived, and hands back the parsed events. It never blocks.
//
// If the daemon isn't running, or goes away, poll() reports DISCONNECTED once
// and then quietly retries every second. On reconnect it re-adds every target,
// so restarting the daemon is just a gap in the graphs.

#ifndef PINGEM_DAEMON_LINK_H
#define PINGEM_DAEMON_LINK_H

#include "../shared/protocol.h"

#include <stdint.h>
#include <string>
#include <vector>

struct TargetSpec {
  int id;
  std::string host;
  double interval;
  int packet_size;
  int flows;            // 0 = no flows
  double probe_rate;    // route probes per ping interval (0 = none; needs flows)
};

enum LinkEventType {
  LINK_CONNECTED,
  LINK_DISCONNECTED,
  LINK_ADDED,         // id, address
  LINK_ERROR,         // id (-1 if not about a target), text
  LINK_PING,          // id, seq, time, flow
  LINK_REPLY,         // id, seq, time, rtt, ttl, address (= who replied), flow
  LINK_UNREACHABLE,   // id, seq, time, address (= who refused), error_type, error_code, flow
  LINK_HOP            // id, flow, ttl (the probe's), time (sent), rtt (< 0: no answer),
                      // address ("*" if none), reached, error_code (-1 unless type 3)
};

struct LinkEvent {
  LinkEventType type;
  int id;
  uint64_t seq;
  double time;
  double rtt;
  int ttl;
  int flow;           // -1 if the target doesn't use flows
  int error_type;
  int error_code;
  bool reached;
  std::string address;
  std::string text;
};

class DaemonLink {
public:
  explicit DaemonLink(const std::vector<TargetSpec>& targets);
  ~DaemonLink();

  // Appends any new events to *events. `now` is any monotonic clock in
  // seconds; it's only used to pace reconnection attempts.
  void poll(double now, std::vector<LinkEvent>* events);

  bool is_connected() const;

  // Changes a target's probe rate, now if connected, and remembers it for
  // reconnects.
  void set_probe_rate(int id, double rate);
  // Stops pinging a target for good.
  void remove_target(int id);

private:
  bool try_connect();
  void disconnect(std::vector<LinkEvent>* events);
  void handle_line(const std::string& line, std::vector<LinkEvent>* events);
  void flush_output(std::vector<LinkEvent>* events);

  std::vector<TargetSpec> targets;
  int fd;
  bool reported_disconnect;
  double next_connect_attempt;
  LineBuffer input;
  std::string output;
};

#endif
