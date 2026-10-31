#include "link_stats.h"

#include <algorithm>
#include <math.h>
#include <stdio.h>

static Estimate unknown() {
  Estimate estimate;
  estimate.known = false;
  estimate.low = 0.0;
  estimate.point = 0.0;
  estimate.high = 0.0;
  estimate.samples = 0.0;
  return estimate;
}

static Estimate exactly(double value) {
  Estimate estimate;
  estimate.known = true;
  estimate.low = value;
  estimate.point = value;
  estimate.high = value;
  estimate.samples = 1e9;
  return estimate;
}

// A floor from the two fastest replies (`second` < 0 if there was only one)
// out of `count`.
static Estimate floor_from(double fastest, double second, double count) {
  Estimate estimate;
  estimate.known = true;
  estimate.point = fastest;
  estimate.high = fastest;
  estimate.low = second < 0.0 ? 0.0 : fastest - (second - fastest);
  if (estimate.low < 0.0) {
    estimate.low = 0.0;
  }
  estimate.samples = count;
  return estimate;
}

// A loss rate of `lost` out of `total`, with its 95% Wilson interval.
static Estimate loss_from(double lost, double total) {
  if (total <= 0.0) {
    return unknown();
  }
  const double z = 1.96;
  double p = lost / total;
  double z2 = z * z;
  double divisor = 1.0 + z2 / total;
  double centre = (p + z2 / (2.0 * total)) / divisor;
  double half = z * sqrt(p * (1.0 - p) / total + z2 / (4.0 * total * total)) / divisor;
  Estimate estimate;
  estimate.known = true;
  estimate.point = p;
  estimate.low = centre - half < 0.0 ? 0.0 : centre - half;
  estimate.high = centre + half > 1.0 ? 1.0 : centre + half;
  if (estimate.low > p) estimate.low = p;     // rounding, at the extremes
  if (estimate.high < p) estimate.high = p;
  estimate.samples = total;
  return estimate;
}

// The better (lower) of two estimates: the whole of whichever has the lower
// point, range and all - the node that sets a figure is the one whose data
// it rests on. (Taking each end's lowest separately would let one node seen
// once, anywhere downstream, widen every range upstream of it to nothing.)
// On a tie, the better-sampled one. True if `into` changed.
static bool take_lower(Estimate* into, const Estimate& other) {
  if (!other.known) {
    return false;
  }
  if (!into->known || other.point < into->point ||
      (other.point == into->point && other.samples > into->samples)) {
    *into = other;
    return true;
  }
  return false;
}

// The two smallest values in a sorted list, merged into (*fastest, *second);
// -1 means none yet.
static void merge_fastest(const float* values, size_t count, double* fastest, double* second) {
  for (size_t i = 0; i < count && i < 2; i++) {
    double value = values[i];
    if (*fastest < 0.0 || value < *fastest) {
      *second = *fastest;
      *fastest = value;
    } else if (*second < 0.0 || value < *second) {
      *second = value;
    }
  }
}

void LinkStats::compute(const RouteGraph& graph, const std::vector<const FlowStats*>& pings) {
  const std::vector<RouteNode>& graph_nodes = graph.get_nodes();
  const std::vector<RouteEdge>& edges = graph.get_edges();
  nodes.assign(graph_nodes.size(), NodeFigures());
  links.assign(edges.size(), LinkFigures());

  // Each node's own figures.
  for (size_t i = 0; i < graph_nodes.size(); i++) {
    const RouteNode& node = graph_nodes[i];
    NodeFigures& figures = nodes[i];
    figures.own_floor = unknown();
    figures.own_loss = unknown();
    if (node.kind == NODE_HERE) {
      figures.own_floor = exactly(0.0);
      figures.own_loss = exactly(0.0);
    } else if (node.kind == NODE_ROUTER) {
      double fastest = -1.0;
      double second = -1.0;
      double count = (double)node.rtts.size();
      if (!node.rtts.empty()) {
        merge_fastest(&node.rtts[0], node.rtts.size(), &fastest, &second);
      }
      // A target: its pings, which far outnumber the probes, for both.
      double lost = 0.0;
      double total = 0.0;
      for (size_t e = 0; e < pings.size(); e++) {
        bool target = e < 64 && (node.target_of & ((uint64_t)1 << e)) != 0;
        if (!target || pings[e] == NULL) {
          continue;
        }
        const FlowStats& stats = *pings[e];
        if (!stats.sorted_rtts.empty()) {
          merge_fastest(&stats.sorted_rtts[0], stats.sorted_rtts.size(), &fastest, &second);
          count += (double)stats.sorted_rtts.size();
        }
        // Pings a router refused never got lost on the way; the refusal is
        // shown on the router that sent it, and isn't loss on any link.
        lost += stats.lost - stats.unreachable;
        total += stats.get_total() - stats.unreachable;
      }
      if (fastest >= 0.0) {
        figures.own_floor = floor_from(fastest, second, count);
      }
      if (total > 0.0) {
        figures.own_loss = loss_from(lost, total);
      } else {
        figures.own_loss = loss_from(node.unanswered, node.answered + node.unanswered);
      }
    }
    // A silent hop has no figures of its own; it takes those beyond it.
    figures.floor = figures.own_floor;
    figures.loss = figures.own_loss;
  }

  // Downstream: each node takes the best of its own and everything after
  // it. Relax along the links until nothing changes (a few passes; bounded,
  // in case a route change ever makes a loop).
  bool changed = true;
  for (size_t pass = 0; changed && pass <= graph_nodes.size(); pass++) {
    changed = false;
    for (size_t k = 0; k < edges.size(); k++) {
      NodeFigures& near = nodes[edges[k].from];
      const NodeFigures& far = nodes[edges[k].to];
      if (take_lower(&near.floor, far.floor)) {
        changed = true;
      }
      if (take_lower(&near.loss, far.loss)) {
        changed = true;
      }
    }
  }

  // Each link: the far end's figures net of the near end's.
  for (size_t k = 0; k < edges.size(); k++) {
    const NodeFigures& near = nodes[edges[k].from];
    const NodeFigures& far = nodes[edges[k].to];
    LinkFigures& link = links[k];
    link.time = unknown();
    link.loss = unknown();
    if (near.floor.known && far.floor.known) {
      link.time.known = true;
      link.time.point = std::max(0.0, far.floor.point - near.floor.point);
      link.time.low = std::max(0.0, far.floor.low - near.floor.high);
      link.time.high = std::max(link.time.point, far.floor.high - near.floor.low);
      if (link.time.low > link.time.point) link.time.low = link.time.point;
      link.time.samples = std::min(near.floor.samples, far.floor.samples);
    }
    if (near.loss.known && far.loss.known) {
      // Losses compound: what gets through to the far end is what got
      // through to the near end, times what gets through the link.
      link.loss.known = true;
      double point = 1.0 - (1.0 - far.loss.point) / std::max(1e-9, 1.0 - near.loss.point);
      double low = 1.0 - (1.0 - far.loss.low) / std::max(1e-9, 1.0 - near.loss.high);
      double high = 1.0 - (1.0 - far.loss.high) / std::max(1e-9, 1.0 - near.loss.low);
      link.loss.point = std::min(1.0, std::max(0.0, point));
      link.loss.low = std::min(link.loss.point, std::max(0.0, low));
      link.loss.high = std::min(1.0, std::max(link.loss.point, high));
      link.loss.samples = std::min(near.loss.samples, far.loss.samples);
    }
  }
}

const NodeFigures& LinkStats::get_node(int node) const {
  return nodes[node];
}

const LinkFigures& LinkStats::get_link(int edge) const {
  return links[edge];
}

// Milliseconds without a unit, as precise as `scale` (the larger of the
// numbers shown together) makes useful; nothing at all is just "0".
static std::string ms_number(double seconds, double scale) {
  char text[32];
  double ms = seconds * 1000.0;
  double scale_ms = scale * 1000.0;
  if (ms < 0.005) {
    return "0";
  }
  if (scale_ms < 1.0) {
    snprintf(text, sizeof(text), "%.2f", ms);
  } else if (scale_ms < 10.0) {
    snprintf(text, sizeof(text), "%.1f", ms);
  } else {
    snprintf(text, sizeof(text), "%.0f", ms);
  }
  return text;
}

// The same for percentages.
static std::string percent_number(double fraction, double scale) {
  char text[32];
  double percent = fraction * 100.0;
  if (percent < 0.05) {
    return "0";
  }
  snprintf(text, sizeof(text), scale * 100.0 < 10.0 ? "%.1f" : "%.0f", percent);
  return text;
}

std::string describe_link_time(const Estimate& time) {
  if (!time.known) {
    return std::string();
  }
  double width = time.high - time.low;
  if (width <= std::max(0.0005, 0.1 * time.point)) {
    return ms_number(time.point, time.point) + "ms";
  }
  return "~" + ms_number(time.low, time.high) + "-" + ms_number(time.high, time.high) + "ms";
}

std::string describe_link_loss(const Estimate& loss) {
  if (!loss.known || loss.point <= 0.0) {
    return std::string();
  }
  double width = loss.high - loss.low;
  if (width <= std::max(0.005, 0.25 * loss.point)) {
    return percent_number(loss.point, loss.point) + "%";
  }
  return "~" + percent_number(loss.low, loss.high) + "-" + percent_number(loss.high, loss.high) + "%";
}
