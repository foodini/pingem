// target_history.h - everything we've learned about one target, in the order
// the packets were sent.
//
// One Sample per ping the daemon sent. A sample starts PENDING when the "ping"
// event arrives, and is resolved exactly once: REPLIED when its reply arrives,
// or LOST when it's been outstanding longer than the loss timeout.
//
// Samples are stored in send order, and send times only increase, so the
// samples for any time window are one contiguous slice of the vector, found
// by binary search. That is what lets the graphs re-tabulate only what's on
// screen instead of the whole history (the old JS walked every event ever
// received on every rebucket).
//
// Sessions: if the daemon goes away, sequence numbers start again at 1 when we
// reconnect. Each connection is a "session"; a sample's index in the vector is
// session_base + (seq - 1). Samples still pending when a session ends are
// marked ABANDONED: we don't know their fate, and a daemon restart isn't
// packet loss.

#ifndef PINGEM_TARGET_HISTORY_H
#define PINGEM_TARGET_HISTORY_H

#include <stdint.h>
#include <string>
#include <vector>

enum SampleState {
  SAMPLE_PENDING,
  SAMPLE_REPLIED,
  SAMPLE_LOST,
  SAMPLE_ABANDONED
};

struct Sample {
  double send_time;     // wall-clock seconds, from the daemon
  float rtt;            // seconds; valid only when REPLIED
  uint8_t state;        // a SampleState
  int8_t flow;          // 0..K-1, or -1 if the target doesn't use flows
};

class TargetHistory {
public:
  explicit TargetHistory(const std::string& name);

  // Events from the daemon.
  void on_added(const std::string& address);
  void on_error(const std::string& text);
  void on_ping(uint64_t seq, double send_time, int flow);
  void on_reply(uint64_t seq, double receive_time, double rtt, int ttl, const std::string& from);
  void on_session_end();

  // Marks samples LOST once they've waited longer than `timeout` seconds.
  // Call once per frame.
  void check_losses(double now, double timeout);

  // Index of the first sample sent at or after `time` (samples.size() if none).
  size_t first_index_at_or_after(double time) const;

  const std::vector<Sample>& get_samples() const;
  const std::string& get_name() const;
  const std::string& get_status() const;   // the one-line status shown above the graph

  // Increases whenever any sample is resolved. Views compare it with the
  // value they last drew to know whether they need to re-tabulate.
  uint64_t get_version() const;

  // How many flows this target's pings are spread over (0 if none). Learned
  // from the flow numbers the daemon reports.
  int get_flow_count() const;

private:
  std::string name;
  std::string address;
  std::string status;
  std::vector<Sample> samples;
  size_t session_base;          // index of seq 1 in the current session
  size_t oldest_pending;        // nothing before this index is PENDING
  uint64_t version;
  int flow_count;
};

#endif
