// tabulation.h - one target's samples, bucketed for the current view.
//
// The graph is a grid: `columns` epochs across, `rows` RTT buckets up. Each
// cell counts the replies that were sent during that epoch and took that long.
// Each column also counts its losses. The summary on the right is the same
// buckets summed across the whole window, plus statistics.
//
// A Tabulation remembers what it was built from (the window and the history's
// version), so build_if_needed() is free when nothing has changed - which is
// most frames.

#ifndef PINGEM_TABULATION_H
#define PINGEM_TABULATION_H

#include "target_history.h"

#include <stdint.h>
#include <vector>

struct ViewWindow {
  double start;
  double end;
  int columns;
  int rows;
  double max_rtt;     // RTT at the top of the graph, seconds

  bool operator==(const ViewWindow& other) const;
};

// The largest RTT of any reply sent within [start, end). 0 if none.
double max_rtt_in_window(const TargetHistory& history, double start, double end);

class Tabulation {
public:
  Tabulation();

  // Rebuilds if the window or the history changed. Returns true if it did.
  bool build_if_needed(const TargetHistory& history, const ViewWindow& window);

  int get_count(int column, int row) const;     // row 0 = lowest RTT
  int get_column_total(int column) const;       // replies + losses
  int get_column_lost(int column) const;
  int get_largest_cell() const;

  int get_summary_bucket(int row) const;
  int get_largest_summary_bucket() const;
  int get_summary_total() const;                // replies + losses
  int get_summary_lost() const;
  int get_summary_replies() const;
  double get_summary_average() const;           // seconds; valid if replies > 0
  double get_summary_percentile(double fraction) const;   // e.g. 0.9

private:
  void build(const TargetHistory& history, const ViewWindow& window);

  bool built;
  ViewWindow built_window;
  uint64_t built_version;
  size_t built_sample_count;

  std::vector<int> counts;           // columns * rows, column-major
  std::vector<int> column_total;
  std::vector<int> column_lost;
  int largest_cell;

  std::vector<int> summary_buckets;
  int largest_summary_bucket;
  int summary_lost;
  std::vector<float> sorted_rtts;    // every reply in the window, ascending
  double summary_rtt_sum;
};

#endif
