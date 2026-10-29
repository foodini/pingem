// route_store.h - every answer to one target's route probes, in send order.
//
// The daemon probes each flow's path one (flow, TTL) at a time and reports
// each answer as a "hop": the router at that TTL on that flow's path, or the
// target itself (reached), or a router that refused the probe (unreachable),
// or nothing at all within a few seconds (silent - shown as "*").
//
// Like TargetHistory, observations are kept sorted by the time the probe was
// SENT, so the ones for any time window are one contiguous slice, found by
// binary search; the route graph is built from exactly the window the
// heatmap is showing. Answers arrive a little out of order (a silent probe is
// only reported after its timeout), so each new one is inserted in place,
// searching back from the end - it's never far.
//
// Router addresses are interned: each distinct address gets a small integer,
// and observations store that.
//
// Route changes: whenever a (flow, TTL) is answered by a different router
// than the last time it was answered, that's a change, and its time is kept.
// The all-routes view marks them on its time strip. (A per-packet load
// balancer makes these constantly - which is worth seeing, too.)

#ifndef PINGEM_ROUTE_STORE_H
#define PINGEM_ROUTE_STORE_H

#include <map>
#include <stdint.h>
#include <string>
#include <vector>

enum HopKind {
  HOP_ROUTER,        // Time Exceeded from a router along the way
  HOP_REACHED,       // an echo reply: the probe got to the target
  HOP_UNREACHABLE,   // Destination Unreachable: the path ends here
  HOP_SILENT         // no answer
};

struct HopObservation {
  double send_time;  // wall clock, seconds
  float rtt;         // seconds; meaningless when SILENT
  int32_t router;    // index into the address table; -1 when SILENT
  int8_t flow;
  uint8_t ttl;
  uint8_t kind;      // a HopKind
  int8_t code;       // UNREACHABLE: the ICMP code; otherwise -1
};

class RouteStore {
public:
  RouteStore();

  void on_hop(int flow, int ttl, double send_time, double rtt, const std::string& address,
              bool reached, int code);

  const std::vector<HopObservation>& get_observations() const;
  size_t first_index_at_or_after(double time) const;

  // Times (probe send times) of route changes, ascending.
  const std::vector<double>& get_change_times() const;

  int get_router_count() const;
  const std::string& get_router_address(int router) const;

  // Increases with every observation, so views know when to rebuild.
  uint64_t get_version() const;

private:
  int intern(const std::string& address);

  std::vector<HopObservation> observations;
  std::vector<double> change_times;
  // The last answer for each (flow, TTL): router * 2 + 1 if it was the
  // target's echo reply, router * 2 if Time Exceeded; -1 if none yet.
  std::vector<int> last_answer;
  std::vector<std::string> addresses;
  std::map<std::string, int> address_index;
  uint64_t version;
};

#endif
