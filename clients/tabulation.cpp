#include "tabulation.h"

#include <algorithm>
#include <math.h>

bool ViewWindow::operator==(const ViewWindow& other) const {
  return start == other.start && end == other.end && columns == other.columns &&
         rows == other.rows && max_rtt == other.max_rtt;
}

double max_rtt_in_window(const TargetHistory& history, double start, double end) {
  const std::vector<Sample>& samples = history.get_samples();
  double max_rtt = 0.0;
  for (size_t i = history.first_index_at_or_after(start); i < samples.size(); i++) {
    const Sample& sample = samples[i];
    if (sample.send_time >= end) {
      break;
    }
    if (sample.state == SAMPLE_REPLIED && sample.rtt > max_rtt) {
      max_rtt = sample.rtt;
    }
  }
  return max_rtt;
}

// ---------------------------------------------------------------------------
// FlowStats
// ---------------------------------------------------------------------------

int FlowStats::get_total() const {
  return (int)sorted_rtts.size() + lost;
}

double FlowStats::get_average() const {
  if (sorted_rtts.empty()) {
    return 0.0;
  }
  return rtt_sum / sorted_rtts.size();
}

double FlowStats::get_percentile(double fraction) const {
  if (sorted_rtts.empty()) {
    return 0.0;
  }
  size_t index = (size_t)floor(sorted_rtts.size() * fraction);
  if (index >= sorted_rtts.size()) {
    index = sorted_rtts.size() - 1;
  }
  return sorted_rtts[index];
}

// ---------------------------------------------------------------------------
// Tabulation
// ---------------------------------------------------------------------------

Tabulation::Tabulation()
    : built(false),
      built_selected_flow(-1),
      built_version(0),
      built_sample_count(0),
      largest_cell(0),
      largest_selected_cell(0),
      largest_flow_bucket(0) {
  reset_stats(&all_flows, 0);
}

void Tabulation::reset_stats(FlowStats* stats, int rows) {
  stats->buckets.assign(rows, 0);
  stats->largest_bucket = 0;
  stats->lost = 0;
  stats->sorted_rtts.clear();
  stats->rtt_sum = 0.0;
}

bool Tabulation::build_if_needed(const TargetHistory& history, const ViewWindow& window,
                                 int selected_flow) {
  if (built && built_window == window && built_selected_flow == selected_flow &&
      built_version == history.get_version() &&
      built_sample_count == history.get_samples().size()) {
    return false;
  }
  build(history, window, selected_flow);
  return true;
}

void Tabulation::build(const TargetHistory& history, const ViewWindow& window,
                       int selected_flow) {
  built = true;
  built_window = window;
  built_selected_flow = selected_flow;
  built_version = history.get_version();
  built_sample_count = history.get_samples().size();

  int columns = window.columns;
  int rows = window.rows;
  int flow_count = history.get_flow_count();

  counts.assign((size_t)columns * rows, 0);
  column_total.assign(columns, 0);
  column_lost.assign(columns, 0);
  largest_cell = 0;

  selected_counts.assign((size_t)columns * rows, 0);
  selected_column_lost.assign(columns, 0);
  largest_selected_cell = 0;

  reset_stats(&all_flows, rows);
  per_flow.resize(flow_count);
  for (int flow = 0; flow < flow_count; flow++) {
    reset_stats(&per_flow[flow], rows);
  }
  largest_flow_bucket = 0;

  double epoch = (window.end - window.start) / columns;
  // A hair above the max, so the largest reply lands in the top row rather
  // than one past it.
  double rtt_scale = rows / (window.max_rtt * 1.0001 + 1e-9);

  const std::vector<Sample>& samples = history.get_samples();
  for (size_t i = history.first_index_at_or_after(window.start); i < samples.size(); i++) {
    const Sample& sample = samples[i];
    if (sample.send_time >= window.end) {
      break;
    }
    if (sample.state != SAMPLE_REPLIED && sample.state != SAMPLE_LOST) {
      continue;   // pending or abandoned: not counted either way
    }

    int column = (int)((sample.send_time - window.start) / epoch);
    if (column < 0) column = 0;
    if (column >= columns) column = columns - 1;
    column_total[column]++;

    int flow = sample.flow;
    FlowStats* flow_stats = NULL;
    if (flow >= 0 && flow < flow_count) {
      flow_stats = &per_flow[flow];
    }
    bool is_selected = selected_flow >= 0 && flow == selected_flow;

    if (sample.state == SAMPLE_LOST) {
      column_lost[column]++;
      all_flows.lost++;
      if (flow_stats != NULL) {
        flow_stats->lost++;
      }
      if (is_selected) {
        selected_column_lost[column]++;
      }
      continue;
    }

    int row = (int)(sample.rtt * rtt_scale);
    if (row < 0) row = 0;
    if (row >= rows) row = rows - 1;
    size_t cell_index = (size_t)column * rows + row;

    int& cell = counts[cell_index];
    cell++;
    if (cell > largest_cell) {
      largest_cell = cell;
    }
    if (is_selected) {
      int& selected_cell = selected_counts[cell_index];
      selected_cell++;
      if (selected_cell > largest_selected_cell) {
        largest_selected_cell = selected_cell;
      }
    }

    int& bucket = all_flows.buckets[row];
    bucket++;
    if (bucket > all_flows.largest_bucket) {
      all_flows.largest_bucket = bucket;
    }
    all_flows.sorted_rtts.push_back(sample.rtt);
    all_flows.rtt_sum += sample.rtt;

    if (flow_stats != NULL) {
      int& flow_bucket = flow_stats->buckets[row];
      flow_bucket++;
      if (flow_bucket > flow_stats->largest_bucket) {
        flow_stats->largest_bucket = flow_bucket;
      }
      if (flow_bucket > largest_flow_bucket) {
        largest_flow_bucket = flow_bucket;
      }
      flow_stats->sorted_rtts.push_back(sample.rtt);
      flow_stats->rtt_sum += sample.rtt;
    }
  }

  // A numeric sort. (The JS version's samples.sort() compared the numbers as
  // strings.)
  std::sort(all_flows.sorted_rtts.begin(), all_flows.sorted_rtts.end());
  for (int flow = 0; flow < flow_count; flow++) {
    std::sort(per_flow[flow].sorted_rtts.begin(), per_flow[flow].sorted_rtts.end());
  }
}

int Tabulation::get_count(int column, int row) const {
  return counts[(size_t)column * built_window.rows + row];
}

int Tabulation::get_column_total(int column) const {
  return column_total[column];
}

int Tabulation::get_column_lost(int column) const {
  return column_lost[column];
}

int Tabulation::get_largest_cell() const {
  return largest_cell;
}

int Tabulation::get_selected_flow() const {
  return built_selected_flow;
}

int Tabulation::get_selected_count(int column, int row) const {
  return selected_counts[(size_t)column * built_window.rows + row];
}

int Tabulation::get_selected_column_lost(int column) const {
  return selected_column_lost[column];
}

int Tabulation::get_largest_selected_cell() const {
  return largest_selected_cell;
}

int Tabulation::get_flow_count() const {
  return (int)per_flow.size();
}

const FlowStats& Tabulation::get_stats(int flow) const {
  if (flow < 0 || flow >= (int)per_flow.size()) {
    return all_flows;
  }
  return per_flow[flow];
}

int Tabulation::get_largest_flow_bucket() const {
  return largest_flow_bucket;
}
