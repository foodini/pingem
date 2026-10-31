// link_stats.h - how much time, and how much loss, each link of the route
// graph adds.
//
// A router's own answers are a poor guide to the traffic passing through
// it: it answers probes on its slow path, late and jumpy, and many limit
// how often they answer at all. But it can't make the hops BEYOND it look
// bad. So each node is judged by the best figures seen at it or anywhere
// downstream of it, up to and including the targets (whose figures come
// from the pings, so the end of every path rests on plenty of data):
//
//   - its floor: the fastest reply from it or from anything past it;
//   - its loss: the lowest loss rate at it or anywhere past it.
//
// A slow or reticent router gets pulled down to what the hops after it
// show, so its own quirks vanish; a long cable, a queue, or a lossy link
// survives, because every hop beyond it pays for it too. A link's added
// time is then the floor at its far end minus the floor at its near end;
// its added loss, the far end's loss net of the near end's. Both can only
// be zero or more.
//
// Uncertainty: with few replies, the fastest seen probably isn't the
// fastest there is. The gap between the fastest and second fastest is a
// standard guess at how far off it is, so a floor is a range, from "fastest
// minus that gap" up to "fastest" (from 0, with a single reply). A loss rate
// is a range too: its 95% confidence interval (Wilson's). A link's figures
// are ranges built from its two ends' - wide when there's little data,
// narrowing to a single value as the data comes in. (A node's downstream
// figure, range and all, is that of whichever node sets it.)
//
// One caveat: a reply's trip back can take a different path than the
// probe's trip out, so time a link "adds" may really be on the way back.

#ifndef PINGEM_LINK_STATS_H
#define PINGEM_LINK_STATS_H

#include "route_graph.h"
#include "tabulation.h"

#include <string>
#include <vector>

// A figure that may only be known roughly: low <= point <= high.
struct Estimate {
  bool known;
  double low;
  double point;
  double high;
  double samples;   // how many replies (or probes, for loss) it rests on
};

// A node's figures: its own, and judged by everything downstream too.
struct NodeFigures {
  Estimate own_floor;     // seconds
  Estimate own_loss;      // 0..1
  Estimate floor;         // the downstream view (see the header)
  Estimate loss;
};

struct LinkFigures {
  Estimate time;          // seconds added
  Estimate loss;          // fraction of the traffic lost on it, 0..1
};

class LinkStats {
public:
  // `pings` has one entry per endpoint of the graph: its pings during the
  // graph's window (NULL if none), for its target.
  void compute(const RouteGraph& graph, const std::vector<const FlowStats*>& pings);

  const NodeFigures& get_node(int node) const;
  const LinkFigures& get_link(int edge) const;

private:
  std::vector<NodeFigures> nodes;
  std::vector<LinkFigures> links;
};

// As short as can be, for the map: "38ms", or "~30-46ms" while it's
// uncertain. Empty if unknown.
std::string describe_link_time(const Estimate& time);
// "2.1%", or "~1.0-6.3%" while it's uncertain. Empty if no loss was seen
// there.
std::string describe_link_loss(const Estimate& loss);

#endif
