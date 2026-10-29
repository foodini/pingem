// tabulation.h - one target's samples, bucketed for the current view.
//
// The graph is a grid: `columns` epochs across, `rows` RTT buckets up. Each
// cell counts the replies that were sent during that epoch and took that long.
// Each column also counts its losses. The summary on the right is the same
// buckets summed across the whole window, plus statistics.
//
// Flows: when the target's pings are spread over K flows, the summary and the
// statistics are also kept per flow, so the summary column can be split into
// one histogram per flow. If some flows are "selected" (one, by clicking its
// histogram; or all the flows that share a link, by clicking it in the route
// graph), the grid and the losses are additionally counted for the selection
// alone, so the graph can show it at full brightness with the rest dimmed.
//
// A Tabulation remembers what it was built from (the window, the selection,
// and the history's version), so build_if_needed() is free when nothing has
// changed - which is most frames.

#ifndef PINGEM_TABULATION_H
#define PINGEM_TABULATION_H

#include "target_history.h"

#include <stdint.h>
#include <string>
#include <vector>

// A set of flows: bit f is flow f. MAX_FLOWS is 64, so one word holds them all.
typedef uint64_t FlowMask;

inline FlowMask flow_bit(int flow) {
  return (FlowMask)1 << flow;
}

// "3", "0,2,5", or "0-3,6": a short list of the flows in a mask.
std::string describe_flow_mask(FlowMask mask);

struct ViewWindow {
  double start;
  double end;
  int columns;
  int rows;
  double max_rtt;     // RTT at the top of the graph, seconds
  // Log scale: the vertical axis is logarithmic from min_rtt (the bottom
  // edge) to max_rtt. Linear scale: from 0 to max_rtt, and min_rtt is unused.
  bool log_scale;
  double min_rtt;

  bool operator==(const ViewWindow& other) const;
};

// Where `rtt` sits on the vertical axis: 0 = bottom edge, 1 = top edge
// (clamped). Everything that maps RTTs to pixels or rows goes through these
// two, so linear and log scale can't drift apart.
double rtt_to_fraction(const ViewWindow& window, double rtt);
double fraction_to_rtt(const ViewWindow& window, double fraction);

// The largest / smallest RTT of any reply sent within [start, end). 0 if none.
double max_rtt_in_window(const TargetHistory& history, double start, double end);
double min_rtt_in_window(const TargetHistory& history, double start, double end);

// Everything the summary statistics need, for all flows or for one.
struct FlowStats {
  std::vector<int> buckets;          // one per RTT row
  int largest_bucket;
  int lost;                          // includes the unreachable ones
  int unreachable;                   // refused with an ICMP error
  std::vector<float> sorted_rtts;    // every reply in the window, ascending
  double rtt_sum;

  int get_total() const;             // replies + losses
  double get_average() const;        // seconds; 0 if no replies
  double get_percentile(double fraction) const;   // e.g. 0.9; 0 if no replies
};

class Tabulation {
public:
  Tabulation();

  // Rebuilds if the window, the selection (0 = none) or the history
  // changed. Returns true if it did.
  bool build_if_needed(const TargetHistory& history, const ViewWindow& window,
                       FlowMask selection);

  // The whole grid, all flows.
  int get_count(int column, int row) const;     // row 0 = lowest RTT
  int get_column_total(int column) const;       // replies + losses, all flows
  int get_column_lost(int column) const;          // includes unreachable
  int get_column_unreachable(int column) const;
  int get_largest_cell() const;

  // The same, for the selected flows only (all zero if none are selected).
  FlowMask get_selection() const;
  int get_selected_count(int column, int row) const;
  int get_selected_column_lost(int column) const;
  int get_largest_selected_cell() const;
  // Statistics for the selected flows together.
  const FlowStats& get_selection_stats() const;

  // Summary statistics: flow -1 means all flows combined.
  int get_flow_count() const;
  const FlowStats& get_stats(int flow) const;
  // The largest bucket in ANY flow's histogram, so the per-flow histograms
  // share one scale and can be compared by eye.
  int get_largest_flow_bucket() const;

private:
  void build(const TargetHistory& history, const ViewWindow& window, FlowMask selection);
  static void reset_stats(FlowStats* stats, int rows);

  bool built;
  ViewWindow built_window;
  FlowMask built_selection;
  uint64_t built_version;
  size_t built_sample_count;

  std::vector<int> counts;            // columns * rows, column-major
  std::vector<int> column_total;
  std::vector<int> column_lost;
  std::vector<int> column_unreachable;
  int largest_cell;

  std::vector<int> selected_counts;   // same layout as counts
  std::vector<int> selected_column_lost;
  int largest_selected_cell;
  FlowStats selection_stats;

  FlowStats all_flows;
  std::vector<FlowStats> per_flow;    // one per flow
  int largest_flow_bucket;
};

#endif
