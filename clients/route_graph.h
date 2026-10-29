// route_graph.h - the paths to one or more targets ("endpoints"), as one
// graph, for one time window.
//
// Built from each endpoint's RouteStore, using the observations in the window
// the heatmaps are showing, so scrolling back in time shows the routes as
// they were then.
//
// Nodes:
//   "here"      - this machine, where every path starts.
//   a router    - anything that answered a probe with Time Exceeded, or
//                 refused one with Destination Unreachable. A refused probe
//                 stops there, so it says nothing about the hops after it;
//                 and when the refusing router is one we've also seen
//                 passing probes on, the refusal is just noted on it - it
//                 doesn't add a link.
//   "*"         - one or more hops in a row that never answered ("*x5" is
//                 five). Routers that don't send Time Exceeded are common.
//                 It's identified by the TTL it starts at and the node before
//                 it, so flows that went different ways before it get
//                 different ones. Until every hop in it has gone unanswered a
//                 few times it's "?" instead: maybe a silent router, maybe
//                 just lost probes.
//
// A flow that got no answer at some hop, where all the flows that came from
// the same place one hop back heard from one router, is taken to have gone
// through that router too: it's a router that answers only some probes
// (rate limiting is common, home routers especially), not a different path.
//   a target    - whatever answered an endpoint's probe with an echo reply.
//                 Usually the endpoint itself; with anycast, whichever copy
//                 of it was nearest - either way, the end of that path.
//
// A node is identified by its ADDRESS, across all endpoints: a router on the
// paths to three endpoints is one node, and so is an address that's one
// endpoint's target and a hop on the way to another (when you ping your own
// router as well as something beyond it). So the picture's shape is the
// network's shape.
//
// Edges join the node a flow reached at TTL n to the one it reached at TTL
// n+1. Each edge records which flows of WHICH endpoints used it. When a
// flow's route changed within the window, its probes at TTL n and n+1 are
// paired up by time, so the old and new routes each appear whole, rather
// than cross-linked.
//
// If the window is too short to hold an answer for some (flow, TTL) - zoomed
// far in - the most recent answer before the window is used instead, so the
// graph doesn't fall apart into fragments.
//
// Traffic share. Pings rotate evenly through an endpoint's flows, so a
// router's share of that endpoint's traffic is the average, over the flows,
// of the fraction of each flow's probes (at that hop, in the window) that it
// answered. A flow that moved halfway through the window counts as half a
// flow; a per-packet load balancer that alternates a flow between two
// routers gives each about half. "Right now" is simpler: the flows whose
// newest probe at that hop it answered.

#ifndef PINGEM_ROUTE_GRAPH_H
#define PINGEM_ROUTE_GRAPH_H

#include "route_store.h"
#include "tabulation.h"   // FlowMask

#include "../third_party/imgui/imgui.h"   // ImVec2

#include <map>
#include <string>
#include <vector>

// One endpoint to build the graph from.
struct RouteEndpoint {
  const RouteStore* store;
  int flow_count;           // as the pings say (the probes may say more)
};

enum RouteNodeKind {
  NODE_HERE,
  NODE_ROUTER,              // a router, a target, or both
  NODE_SILENT
};

// How one endpoint's traffic uses a node.
struct EndpointUse {
  FlowMask flows;           // flows whose paths go through it
  FlowMask now_flows;       // ...as of each flow's newest probe at that hop
  double share;             // estimated share of the traffic, 0..1 (see above)
};

struct RouteNode {
  std::string key;          // stable identity, for keeping layouts across rebuilds
  RouteNodeKind kind;
  std::string address;      // ROUTER: its address; else empty
  uint64_t target_of;       // bit e: endpoint e's probes got an echo reply from it
  bool refused;             // answered Destination Unreachable
  int refused_code;
  int refused_count;        // how many probes it refused
  int run_min;              // SILENT: how many hops in a row (as few as / as many as;
  int run_max;              //   different flows' runs can differ in length)
  bool uncertain;           // SILENT: not yet unanswered often enough to be sure ("?")
  int hop;                  // the TTL it's most often seen at (here = 0)
  int layer;                // for the one-endpoint layout: hop, but targets go last
  std::vector<EndpointUse> uses;   // one per endpoint
  std::vector<float> rtts;  // every answer in the window, sorted
  int answered;             // probes it answered
  double unanswered;        // its share of the unanswered probes at its (flow, TTL)s
  std::vector<int> ttls;    // TTLs it was seen at, ascending, distinct
};

struct RouteEdge {
  int from;                 // node indexes
  int to;
  std::vector<FlowMask> flows;   // one per endpoint
};

class RouteGraph {
public:
  RouteGraph();

  // Rebuilds from `endpoints` for [start, end). Returns false (and does
  // nothing) if nothing that matters has changed since the last build.
  bool build_if_needed(const std::vector<RouteEndpoint>& endpoints, double start, double end);

  const std::vector<RouteNode>& get_nodes() const;
  const std::vector<RouteEdge>& get_edges() const;
  int get_endpoint_count() const;
  int get_flow_count(int endpoint) const;
  // The main path to an endpoint: at each TTL, the node most often seen
  // there, from TTL 1 to the target. Empty if it has no data.
  const std::vector<int>& get_spine(int endpoint) const;
  bool is_empty() const;      // no probe answers in or before the window
  int get_last_layer() const; // the one-endpoint layout's last layer

private:
  void build(const std::vector<RouteEndpoint>& endpoints, double start, double end);
  struct ShareSums;
  void add_endpoint(int endpoint, const RouteEndpoint& source, double start, double end);
  void add_share(int node, int flow, double fraction, int flow_count,
                 std::map<int, ShareSums>* shares);
  int add_silent_run(const std::string& key, int endpoint, int flow, int flow_count,
                     const std::vector<std::pair<int, int> >& silences,
                     std::map<int, ShareSums>* shares,
                     std::vector<std::map<int, int> >* spine_counts);
  int node_for(const std::string& key, RouteNodeKind kind, const std::string& address);

  std::vector<RouteNode> nodes;
  std::vector<RouteEdge> edges;
  std::map<std::string, int> node_index;
  std::vector<int> flow_counts;
  std::vector<std::vector<int> > spines;
  int last_layer;

  // Collected while building.
  std::map<std::pair<int, int>, std::vector<FlowMask> > edge_flows;   // (from, to)
  std::map<int, std::map<int, int> > ttl_counts;                      // node -> TTL -> count

  bool built;
  double built_start;
  double built_end;
  std::vector<const RouteStore*> built_stores;
  std::vector<uint64_t> built_versions;
  std::vector<int> built_flow_counts;
};

// Positions for a graph's nodes, by node key, in units of the drawing
// area's height (y down) - so a layout survives the window being resized. A layout is computed once and then kept: nodes never
// move on their own, because a picture that rearranges itself while you're
// reading it is worse than a slightly stale one. RouteView offers a button
// when the graph has nodes the layout doesn't place.
struct RouteLayout {
  std::map<std::string, ImVec2> positions;

  // One endpoint: layers by TTL along the diagonal from bottom-left
  // ("here") to top-right (the target); where flows split, the branches
  // spread out across that diagonal.
  void compute(const RouteGraph& graph, float aspect);   // aspect = width / height

  // Several endpoints: a tree to start (nothing crossed), then physics with
  // everything free to move (see the comment above compute_multi in
  // route_graph.cpp). The map can come out any size; positions are in units
  // of the drawing area's height, with the map's top-left at (0, 0).
  //
  // label_sizes: each node's label (width, height), indexed like the
  // graph's nodes; dot_radius: a node's radius; edge_widths: each link's
  // drawn width (its bundle of stripes), indexed like the graph's edges.
  // All in units of the area's height.
  void compute_multi(const RouteGraph& graph, const std::vector<ImVec2>& label_sizes,
                     float dot_radius, const std::vector<float>& edge_widths);

  bool places_all(const RouteGraph& graph) const;
};

#endif
