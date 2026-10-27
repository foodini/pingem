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

Tabulation::Tabulation()
    : built(false),
      built_version(0),
      built_sample_count(0),
      largest_cell(0),
      largest_summary_bucket(0),
      summary_lost(0),
      summary_rtt_sum(0.0) {
}

bool Tabulation::build_if_needed(const TargetHistory& history, const ViewWindow& window) {
  if (built && built_window == window && built_version == history.get_version() &&
      built_sample_count == history.get_samples().size()) {
    return false;
  }
  build(history, window);
  return true;
}

void Tabulation::build(const TargetHistory& history, const ViewWindow& window) {
  built = true;
  built_window = window;
  built_version = history.get_version();
  built_sample_count = history.get_samples().size();

  int columns = window.columns;
  int rows = window.rows;
  counts.assign((size_t)columns * rows, 0);
  column_total.assign(columns, 0);
  column_lost.assign(columns, 0);
  summary_buckets.assign(rows, 0);
  sorted_rtts.clear();
  summary_lost = 0;
  summary_rtt_sum = 0.0;
  largest_cell = 0;
  largest_summary_bucket = 0;

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

    if (sample.state == SAMPLE_LOST) {
      column_lost[column]++;
      summary_lost++;
      continue;
    }

    int row = (int)(sample.rtt * rtt_scale);
    if (row < 0) row = 0;
    if (row >= rows) row = rows - 1;

    int& cell = counts[(size_t)column * rows + row];
    cell++;
    if (cell > largest_cell) {
      largest_cell = cell;
    }
    int& bucket = summary_buckets[row];
    bucket++;
    if (bucket > largest_summary_bucket) {
      largest_summary_bucket = bucket;
    }
    sorted_rtts.push_back(sample.rtt);
    summary_rtt_sum += sample.rtt;
  }

  // A numeric sort. (The JS version's samples.sort() compared the numbers as
  // strings.)
  std::sort(sorted_rtts.begin(), sorted_rtts.end());
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

int Tabulation::get_summary_bucket(int row) const {
  return summary_buckets[row];
}

int Tabulation::get_largest_summary_bucket() const {
  return largest_summary_bucket;
}

int Tabulation::get_summary_total() const {
  return (int)sorted_rtts.size() + summary_lost;
}

int Tabulation::get_summary_lost() const {
  return summary_lost;
}

int Tabulation::get_summary_replies() const {
  return (int)sorted_rtts.size();
}

double Tabulation::get_summary_average() const {
  if (sorted_rtts.empty()) {
    return 0.0;
  }
  return summary_rtt_sum / sorted_rtts.size();
}

double Tabulation::get_summary_percentile(double fraction) const {
  if (sorted_rtts.empty()) {
    return 0.0;
  }
  size_t index = (size_t)floor(sorted_rtts.size() * fraction);
  if (index >= sorted_rtts.size()) {
    index = sorted_rtts.size() - 1;
  }
  return sorted_rtts[index];
}
