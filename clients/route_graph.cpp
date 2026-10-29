#include "route_graph.h"

#include "../shared/protocol.h"   // MAX_PROBE_TTL

#include <algorithm>
#include <math.h>
#include <stdio.h>

// How far before the window to look for an answer for a (flow, TTL) that has
// none inside it.
static const double BACKFILL_SECONDS = 300.0;

static const int TTLS = MAX_PROBE_TTL + 1;

// A hop counts as silent ("*") once this many probes to it went unanswered;
// until then it's "?" - maybe a router that doesn't answer, maybe just lost
// probes.
static const int SILENT_CONFIRMATIONS = 3;

static FlowMask all_flows(int flow_count) {
  return flow_count >= 64 ? ~(FlowMask)0 : flow_bit(flow_count) - 1;
}

RouteGraph::RouteGraph()
    : last_layer(0), built(false), built_start(0.0), built_end(0.0) {
}

const std::vector<RouteNode>& RouteGraph::get_nodes() const {
  return nodes;
}

const std::vector<RouteEdge>& RouteGraph::get_edges() const {
  return edges;
}

int RouteGraph::get_endpoint_count() const {
  return (int)flow_counts.size();
}

int RouteGraph::get_flow_count(int endpoint) const {
  return flow_counts[endpoint];
}

const std::vector<int>& RouteGraph::get_spine(int endpoint) const {
  return spines[endpoint];
}

bool RouteGraph::is_empty() const {
  return nodes.size() <= 1;   // just "here"
}

int RouteGraph::get_last_layer() const {
  return last_layer;
}

bool RouteGraph::build_if_needed(const std::vector<RouteEndpoint>& endpoints, double start,
                                 double end) {
  bool same = built && built_start == start && built_end == end &&
              built_stores.size() == endpoints.size();
  for (size_t e = 0; same && e < endpoints.size(); e++) {
    same = built_stores[e] == endpoints[e].store &&
           built_versions[e] == endpoints[e].store->get_version() &&
           built_flow_counts[e] == endpoints[e].flow_count;
  }
  if (same) {
    return false;
  }
  built = true;
  built_start = start;
  built_end = end;
  built_stores.clear();
  built_versions.clear();
  built_flow_counts.clear();
  for (size_t e = 0; e < endpoints.size(); e++) {
    built_stores.push_back(endpoints[e].store);
    built_versions.push_back(endpoints[e].store->get_version());
    built_flow_counts.push_back(endpoints[e].flow_count);
  }
  build(endpoints, start, end);
  return true;
}

int RouteGraph::node_for(const std::string& key, RouteNodeKind kind,
                         const std::string& address) {
  std::map<std::string, int>::iterator found = node_index.find(key);
  if (found != node_index.end()) {
    return found->second;
  }
  RouteNode node;
  node.key = key;
  node.kind = kind;
  node.address = address;
  node.target_of = 0;
  node.refused = false;
  node.refused_code = -1;
  node.refused_count = 0;
  node.run_min = 0;
  node.run_max = 0;
  node.uncertain = false;
  node.hop = 0;
  node.layer = 0;
  EndpointUse unused;
  unused.flows = 0;
  unused.now_flows = 0;
  unused.share = 0.0;
  node.uses.assign(flow_counts.size(), unused);
  node.answered = 0;
  node.unanswered = 0.0;
  int index = (int)nodes.size();
  nodes.push_back(node);
  node_index[key] = index;
  return index;
}

// One step along a flow's path: the node a probe found, and when it was sent.
// time < 0 means "stands for every probe at this TTL" (here, and stars).
struct PathPoint {
  double time;
  int node;
};

typedef std::map<std::pair<int, int>, std::vector<FlowMask> > EdgeFlows;

static void add_edge(EdgeFlows* edge_flows, int endpoints, int from, int to, int endpoint,
                     int flow) {
  if (from == to) {
    return;   // some routers answer at two TTLs in a row; not a real link
  }
  std::vector<FlowMask>& flows = (*edge_flows)[std::make_pair(from, to)];
  if (flows.empty()) {
    flows.assign(endpoints, 0);
  }
  flows[endpoint] |= flow_bit(flow);
}

// Joins every point at TTL n+1 (`current`) to the point at TTL n
// (`previous`) whose probe was sent nearest in time. Both lists are in time
// order, so one forward pass does it.
static void join(const std::vector<PathPoint>& previous, const std::vector<PathPoint>& current,
                 int endpoints, int endpoint, int flow, EdgeFlows* edge_flows) {
  if (previous.empty() || current.empty()) {
    return;
  }
  if (current[0].time < 0.0) {
    // A star: every distinct node before it leads to it.
    for (size_t i = 0; i < previous.size(); i++) {
      add_edge(edge_flows, endpoints, previous[i].node, current[0].node, endpoint, flow);
    }
    return;
  }
  if (previous[0].time < 0.0) {
    for (size_t i = 0; i < current.size(); i++) {
      add_edge(edge_flows, endpoints, previous[0].node, current[i].node, endpoint, flow);
    }
    return;
  }
  size_t p = 0;
  for (size_t i = 0; i < current.size(); i++) {
    double t = current[i].time;
    while (p + 1 < previous.size() &&
           fabs(previous[p + 1].time - t) <= fabs(previous[p].time - t)) {
      p++;
    }
    add_edge(edge_flows, endpoints, previous[p].node, current[i].node, endpoint, flow);
  }
}

// The node seen most often among `points`.
static int most_common_node(const std::vector<PathPoint>& points) {
  std::map<int, int> counts;
  int best = points[0].node;
  int best_count = 0;
  for (size_t i = 0; i < points.size(); i++) {
    int count = ++counts[points[i].node];
    if (count > best_count) {
      best_count = count;
      best = points[i].node;
    }
  }
  return best;
}

void RouteGraph::build(const std::vector<RouteEndpoint>& endpoints, double start, double end) {
  nodes.clear();
  edges.clear();
  node_index.clear();
  edge_flows.clear();
  ttl_counts.clear();
  last_layer = 0;
  int endpoint_count = (int)endpoints.size();
  flow_counts.assign(endpoint_count, 0);
  spines.assign(endpoint_count, std::vector<int>());

  // The flow counts first: every node carries a use per endpoint, sized to
  // its flows. What the pings say, or more if the probes say so.
  for (int e = 0; e < endpoint_count; e++) {
    const std::vector<HopObservation>& observations = endpoints[e].store->get_observations();
    int count = endpoints[e].flow_count;
    for (size_t i = endpoints[e].store->first_index_at_or_after(start);
         i < observations.size() && observations[i].send_time < end; i++) {
      if (observations[i].flow >= count) {
        count = observations[i].flow + 1;
      }
    }
    flow_counts[e] = count;
  }

  int here = node_for("here", NODE_HERE, "");
  for (int e = 0; e < endpoint_count; e++) {
    nodes[here].uses[e].flows = all_flows(flow_counts[e]);
    nodes[here].uses[e].now_flows = all_flows(flow_counts[e]);
    nodes[here].uses[e].share = 1.0;
  }

  for (int e = 0; e < endpoint_count; e++) {
    add_endpoint(e, endpoints[e], start, end);
  }

  // Each node's hop is the TTL it's most often seen at. For the one-endpoint
  // layout, targets go one layer beyond everything else, so the target is
  // always the far corner.
  bool any_target = false;
  for (size_t i = 0; i < nodes.size(); i++) {
    RouteNode& node = nodes[i];
    std::sort(node.rtts.begin(), node.rtts.end());
    std::map<int, int>& counts = ttl_counts[(int)i];
    int best_count = 0;
    for (std::map<int, int>::iterator it = counts.begin(); it != counts.end(); ++it) {
      node.ttls.push_back(it->first);
      if (it->second > best_count) {
        best_count = it->second;
        node.hop = it->first;
      }
    }
    if (node.kind == NODE_SILENT && !node.ttls.empty()) {
      // A run sits where it starts; and it's only "certainly silent" once
      // every hop in it has gone unanswered a few times. Before that, it may
      // just be probes that got lost.
      node.hop = node.ttls[0];
      for (std::map<int, int>::iterator it = counts.begin(); it != counts.end(); ++it) {
        if (it->second < SILENT_CONFIRMATIONS) {
          node.uncertain = true;
        }
      }
    }
    node.layer = node.hop;
    if (node.target_of != 0) {
      any_target = true;
    } else if (node.layer > last_layer) {
      last_layer = node.layer;
    }
  }
  if (any_target) {
    last_layer++;
    for (size_t i = 0; i < nodes.size(); i++) {
      if (nodes[i].target_of != 0) {
        nodes[i].layer = last_layer;
      }
    }
  }

  // Shortcuts: when a flow wasn't probed at some TTL during the window, its
  // path links straight from the hop before to the hop after. If the hop it
  // skipped is known - there's a link from the one to it and from it to the
  // other - the shortcut is just a gap in the data, so its flows go along
  // the two real links instead.
  bool removed = true;
  while (removed) {
    removed = false;
    for (EdgeFlows::iterator it = edge_flows.begin(); it != edge_flows.end() && !removed; ++it) {
      int from = it->first.first;
      int to = it->first.second;
      for (EdgeFlows::iterator first = edge_flows.lower_bound(std::make_pair(from, -1));
           first != edge_flows.end() && first->first.first == from; ++first) {
        int middle = first->first.second;
        if (middle == to) {
          continue;
        }
        EdgeFlows::iterator second = edge_flows.find(std::make_pair(middle, to));
        if (second == edge_flows.end()) {
          continue;
        }
        for (size_t e = 0; e < it->second.size(); e++) {
          first->second[e] |= it->second[e];
          second->second[e] |= it->second[e];
          nodes[middle].uses[e].flows |= it->second[e];
        }
        edge_flows.erase(it);
        removed = true;
        break;
      }
    }
  }

  for (EdgeFlows::iterator it = edge_flows.begin(); it != edge_flows.end(); ++it) {
    RouteEdge edge;
    edge.from = it->first.first;
    edge.to = it->first.second;
    edge.flows = it->second;
    edges.push_back(edge);
  }
}

// For the traffic share: per node, per flow, the sum over the cells (TTLs)
// where it appeared of the fraction of that cell's answers it gave, and how
// many such cells.
struct RouteGraph::ShareSums {
  std::vector<double> fraction_sum;
  std::vector<int> cells;
};

void RouteGraph::add_share(int node, int flow, double fraction, int flow_count,
                           std::map<int, ShareSums>* shares) {
  ShareSums& sums = (*shares)[node];
  if (sums.cells.empty()) {
    sums.fraction_sum.assign(flow_count, 0.0);
    sums.cells.assign(flow_count, 0);
  }
  sums.fraction_sum[flow] += fraction;
  sums.cells[flow]++;
}

// A run of silent hops on one flow, ended (by an answer, or by the end of
// the path): one node for the whole run, keyed by where it starts and the
// node before it, so flows that went quiet at the same place share it.
int RouteGraph::add_silent_run(const std::string& key, int endpoint, int flow, int flow_count,
                               const std::vector<std::pair<int, int> >& silences,
                               std::map<int, ShareSums>* shares,
                               std::vector<std::map<int, int> >* spine_counts) {
  int node = node_for(key, NODE_SILENT, "");
  RouteNode& run = nodes[node];
  EndpointUse& use = run.uses[endpoint];
  use.flows |= flow_bit(flow);
  use.now_flows |= flow_bit(flow);
  int length = (int)silences.size();
  if (run.run_min == 0 || length < run.run_min) run.run_min = length;
  if (length > run.run_max) run.run_max = length;
  for (size_t k = 0; k < silences.size(); k++) {
    int ttl = silences[k].first;
    int silent = silences[k].second;
    run.unanswered += silent;
    ttl_counts[node][ttl] += silent;
    (*spine_counts)[ttl][node] += silent;
  }
  add_share(node, flow, 1.0, flow_count, shares);
  return node;
}

// What happened at one (flow, TTL) during the build.
enum CellOutcome {
  CELL_SKIPPED,    // not probed (or only refusals): as if the hop weren't there
  CELL_ANSWERED,   // answered, or inferred from the other flows
  CELL_SILENT      // silent: part of a run of silent hops
};

// The path-walking state of one flow.
struct FlowWalk {
  int last_answer;                  // TTL of the furthest answer (0 = none)
  int last_probed;                  // TTL of the furthest probe
  std::vector<PathPoint> previous;  // the points at the last resolved TTL
  int previous_main;                // the most common node among them
  int previous_ttl;                 // that TTL (0 = "here")
  bool reached_end;                 // the last resolved TTL was the target
  std::vector<std::pair<int, int> > run;   // silent hops since then: (TTL, silences)
};

void RouteGraph::add_endpoint(int endpoint, const RouteEndpoint& source, double start,
                              double end) {
  const RouteStore& store = *source.store;
  const std::vector<HopObservation>& observations = store.get_observations();
  size_t first = store.first_index_at_or_after(start);
  int flow_count = flow_counts[endpoint];
  int endpoint_count = (int)flow_counts.size();

  // Sort the window's observations into cells, one per (flow, TTL).
  std::vector<std::vector<int> > cells((size_t)flow_count * TTLS);
  for (size_t i = first; i < observations.size(); i++) {
    const HopObservation& observation = observations[i];
    if (observation.send_time >= end) {
      break;
    }
    if (observation.flow < flow_count && observation.ttl < TTLS) {
      cells[(size_t)observation.flow * TTLS + observation.ttl].push_back((int)i);
    }
  }
  // Backfill empty cells with the newest observation before the window.
  for (size_t i = first; i > 0; i--) {
    const HopObservation& observation = observations[i - 1];
    if (observation.send_time < start - BACKFILL_SECONDS) {
      break;
    }
    if (observation.flow < flow_count && observation.ttl < TTLS) {
      std::vector<int>& cell = cells[(size_t)observation.flow * TTLS + observation.ttl];
      if (cell.empty()) {
        cell.push_back((int)(i - 1));
      }
    }
  }

  // Routers seen passing probes on. A refusal from one of these is noted on
  // it, but isn't a hop on any path (see the header).
  std::vector<bool> passes(store.get_router_count(), false);
  for (size_t c = 0; c < cells.size(); c++) {
    for (size_t k = 0; k < cells[c].size(); k++) {
      const HopObservation& observation = observations[cells[c][k]];
      if (observation.kind == HOP_ROUTER) {
        passes[observation.router] = true;
      }
    }
  }

  int here = node_index["here"];
  std::map<int, ShareSums> shares;
  // How often each node was seen at each TTL on this endpoint's paths, for
  // its spine.
  std::vector<std::map<int, int> > spine_counts(TTLS);

  std::vector<FlowWalk> walks(flow_count);
  int furthest = 0;
  for (int flow = 0; flow < flow_count; flow++) {
    FlowWalk& walk = walks[flow];
    walk.last_answer = 0;
    walk.last_probed = 0;
    for (int ttl = 1; ttl < TTLS; ttl++) {
      const std::vector<int>& cell = cells[(size_t)flow * TTLS + ttl];
      for (size_t k = 0; k < cell.size(); k++) {
        walk.last_probed = ttl;
        if (observations[cell[k]].kind != HOP_SILENT) {
          walk.last_answer = ttl;
        }
      }
    }
    PathPoint start_point;
    start_point.time = -1.0;
    start_point.node = here;
    walk.previous.assign(1, start_point);
    walk.previous_main = here;
    walk.previous_ttl = 0;
    walk.reached_end = false;
    if (walk.last_answer > furthest) {
      furthest = walk.last_answer;
    }
  }

  // Walk all the flows together, one TTL at a time, so that a flow that got
  // no answer at some TTL can look at what the OTHER flows saw there.
  std::vector<CellOutcome> outcome(flow_count);
  std::vector<int> silences(flow_count);
  std::vector<std::vector<PathPoint> > current(flow_count);
  for (int ttl = 1; ttl <= furthest; ttl++) {
    // First, the answers.
    for (int flow = 0; flow < flow_count; flow++) {
      outcome[flow] = CELL_SKIPPED;
      current[flow].clear();
      if (ttl > walks[flow].last_answer) {
        continue;
      }
      const std::vector<int>& cell = cells[(size_t)flow * TTLS + ttl];
      int answers = 0;
      int silent = 0;
      for (size_t k = 0; k < cell.size(); k++) {
        const HopObservation& observation = observations[cell[k]];
        if (observation.kind == HOP_SILENT) {
          silent++;
        } else if (observation.kind == HOP_UNREACHABLE && passes[observation.router]) {
          // Noted on the router, and otherwise left out.
          const std::string& address = store.get_router_address(observation.router);
          RouteNode& refuser = nodes[node_for("a" + address, NODE_ROUTER, address)];
          refuser.refused = true;
          refuser.refused_code = observation.code;
          refuser.refused_count++;
        } else {
          answers++;
        }
      }
      silences[flow] = silent;
      if (answers == 0) {
        outcome[flow] = silent > 0 ? CELL_SILENT : CELL_SKIPPED;
        continue;
      }
      outcome[flow] = CELL_ANSWERED;

      std::map<int, int> answers_by_node;
      int newest_node = -1;
      double newest_time = 0.0;
      for (size_t k = 0; k < cell.size(); k++) {
        const HopObservation& observation = observations[cell[k]];
        if (observation.kind == HOP_SILENT ||
            (observation.kind == HOP_UNREACHABLE && passes[observation.router])) {
          continue;
        }
        const std::string& address = store.get_router_address(observation.router);
        int node = node_for("a" + address, NODE_ROUTER, address);
        RouteNode& n = nodes[node];
        if (observation.kind == HOP_REACHED) {
          n.target_of |= (uint64_t)1 << (endpoint < 64 ? endpoint : 63);
        } else if (observation.kind == HOP_UNREACHABLE) {
          n.refused = true;
          n.refused_code = observation.code;
          n.refused_count++;
        }
        n.uses[endpoint].flows |= flow_bit(flow);
        n.rtts.push_back(observation.rtt);
        n.answered++;
        answers_by_node[node]++;
        ttl_counts[node][ttl]++;
        spine_counts[ttl][node]++;
        if (newest_node < 0 || observation.send_time >= newest_time) {
          newest_node = node;
          newest_time = observation.send_time;
        }
        PathPoint point;
        point.time = observation.send_time;
        point.node = node;
        current[flow].push_back(point);
      }
      nodes[newest_node].uses[endpoint].now_flows |= flow_bit(flow);
      // Unanswered probes at this hop are shared among whoever answered the
      // others: a router that answers half its probes (rate limiting is
      // common) shows a 50% response rate. And each answerer's share of this
      // cell's answers is its share of this flow here.
      for (std::map<int, int>::iterator it = answers_by_node.begin();
           it != answers_by_node.end(); ++it) {
        nodes[it->first].unanswered += (double)silent * it->second / answers;
        add_share(it->first, flow, (double)it->second / answers, flow_count, &shares);
      }
    }

    // Then the silences. A flow that heard nothing at this TTL, where every
    // flow that came from the same node one hop back heard from the SAME
    // router, almost certainly went through that router too - which just
    // didn't answer (routers rate-limit Time Exceeded; home routers
    // especially). So it goes through that router, whose answer rate shows
    // the silence. Otherwise it's a silent hop.
    for (int flow = 0; flow < flow_count; flow++) {
      if (outcome[flow] != CELL_SILENT) {
        continue;
      }
      FlowWalk& walk = walks[flow];
      int candidate = -1;
      bool unique = true;
      if (walk.previous_ttl == ttl - 1 && walk.run.empty()) {
        for (int other = 0; other < flow_count; other++) {
          const FlowWalk& other_walk = walks[other];
          if (other == flow || outcome[other] != CELL_ANSWERED ||
              other_walk.previous_ttl != ttl - 1 ||
              other_walk.previous_main != walk.previous_main) {
            continue;
          }
          for (size_t k = 0; k < current[other].size(); k++) {
            int node = current[other][k].node;
            if (candidate < 0) {
              candidate = node;
            } else if (node != candidate) {
              unique = false;
            }
          }
        }
      }
      if (candidate >= 0 && unique && nodes[candidate].target_of == 0) {
        RouteNode& n = nodes[candidate];
        n.uses[endpoint].flows |= flow_bit(flow);
        n.uses[endpoint].now_flows |= flow_bit(flow);
        n.unanswered += silences[flow];
        add_share(candidate, flow, 1.0, flow_count, &shares);
        PathPoint point;
        point.time = -1.0;
        point.node = candidate;
        current[flow].assign(1, point);
        outcome[flow] = CELL_ANSWERED;
      } else {
        walk.run.push_back(std::make_pair(ttl, silences[flow]));
      }
    }

    // Join each flow's answer to where it was before - through the run of
    // silent hops in between, if there was one.
    for (int flow = 0; flow < flow_count; flow++) {
      if (outcome[flow] != CELL_ANSWERED) {
        continue;
      }
      FlowWalk& walk = walks[flow];
      if (!walk.run.empty()) {
        char key[64];
        snprintf(key, sizeof(key), "~%d<", walk.run[0].first);
        int run = add_silent_run(key + nodes[walk.previous_main].key, endpoint, flow, flow_count,
                                 walk.run, &shares, &spine_counts);
        std::vector<PathPoint> run_point(1);
        run_point[0].time = -1.0;
        run_point[0].node = run;
        join(walk.previous, run_point, endpoint_count, endpoint, flow, &edge_flows);
        walk.previous = run_point;
        walk.run.clear();
      }
      join(walk.previous, current[flow], endpoint_count, endpoint, flow, &edge_flows);
      walk.previous = current[flow];
      walk.previous_main = most_common_node(current[flow]);
      walk.previous_ttl = ttl;
      walk.reached_end = false;
      for (size_t k = 0; k < current[flow].size(); k++) {
        if (nodes[current[flow][k].node].target_of & ((uint64_t)1 << (endpoint < 64 ? endpoint : 63))) {
          walk.reached_end = true;
        }
      }
    }
  }

  // Probed further and heard nothing: the path fades out into a run of
  // silent hops.
  for (int flow = 0; flow < flow_count; flow++) {
    FlowWalk& walk = walks[flow];
    if (walk.last_answer == 0 || walk.reached_end || walk.last_probed <= walk.last_answer) {
      continue;
    }
    std::vector<std::pair<int, int> > fade = walk.run;
    for (int ttl = walk.last_answer + 1; ttl <= walk.last_probed; ttl++) {
      int silent = (int)cells[(size_t)flow * TTLS + ttl].size();
      if (silent > 0) {
        fade.push_back(std::make_pair(ttl, silent));
      }
    }
    if (fade.empty()) {
      continue;
    }
    int run = add_silent_run("~end<" + nodes[walk.previous_main].key, endpoint, flow, flow_count,
                             fade, &shares, &spine_counts);
    std::vector<PathPoint> run_point(1);
    run_point[0].time = -1.0;
    run_point[0].node = run;
    join(walk.previous, run_point, endpoint_count, endpoint, flow, &edge_flows);
  }

  // Traffic shares: the average over ALL the endpoint's flows (a flow that
  // never went through a node contributes 0).
  for (std::map<int, ShareSums>::iterator it = shares.begin(); it != shares.end(); ++it) {
    double total = 0.0;
    for (int flow = 0; flow < flow_count; flow++) {
      if (it->second.cells[flow] > 0) {
        total += it->second.fraction_sum[flow] / it->second.cells[flow];
      }
    }
    nodes[it->first].uses[endpoint].share = flow_count > 0 ? total / flow_count : 0.0;
  }

  // The spine: at each TTL the node most often seen, until the target.
  uint64_t target_bit = (uint64_t)1 << (endpoint < 64 ? endpoint : 63);
  std::vector<int>& spine = spines[endpoint];
  for (int ttl = 1; ttl < TTLS; ttl++) {
    int best = -1;
    int best_count = 0;
    for (std::map<int, int>::iterator it = spine_counts[ttl].begin();
         it != spine_counts[ttl].end(); ++it) {
      if (it->second > best_count) {
        best_count = it->second;
        best = it->first;
      }
    }
    if (best < 0) {
      continue;
    }
    if (spine.empty() || spine.back() != best) {   // a run spans several TTLs
      spine.push_back(best);
    }
    if (nodes[best].target_of & target_bit) {
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

// For sorting a layer's nodes by where their predecessors are.
struct LayerSlot {
  int node;
  double barycenter;
  std::string key;
};

static bool slot_less(const LayerSlot& a, const LayerSlot& b) {
  if (a.barycenter != b.barycenter) {
    return a.barycenter < b.barycenter;
  }
  return a.key < b.key;
}

void RouteLayout::compute(const RouteGraph& graph, float aspect) {
  positions.clear();
  const std::vector<RouteNode>& nodes = graph.get_nodes();
  const std::vector<RouteEdge>& edges = graph.get_edges();
  int last_layer = graph.get_last_layer();
  if (last_layer < 1) {
    last_layer = 1;
  }

  // Each node's offset across the diagonal, in "slots" (1 = the spacing
  // between neighbours). Layer by layer from "here": a node goes at the
  // average offset of the nodes that lead to it (so paths run straight where
  // they can), then neighbours are pushed apart to at least one slot.
  std::vector<double> offset(nodes.size(), 0.0);
  std::vector<std::vector<int> > layers(last_layer + 1);
  for (size_t i = 0; i < nodes.size(); i++) {
    int layer = nodes[i].layer;
    if (layer < 0) layer = 0;
    if (layer > last_layer) layer = last_layer;
    layers[layer].push_back((int)i);
  }
  double widest = 0.0;
  for (int layer = 0; layer <= last_layer; layer++) {
    std::vector<LayerSlot> slots;
    for (size_t k = 0; k < layers[layer].size(); k++) {
      int node = layers[layer][k];
      double sum = 0.0;
      int count = 0;
      for (size_t e = 0; e < edges.size(); e++) {
        if (edges[e].to == node && nodes[edges[e].from].layer < layer) {
          sum += offset[edges[e].from];
          count++;
        }
      }
      LayerSlot slot;
      slot.node = node;
      slot.barycenter = count > 0 ? sum / count : 0.0;
      slot.key = nodes[node].key;
      slots.push_back(slot);
    }
    std::sort(slots.begin(), slots.end(), slot_less);
    if (slots.empty()) {
      continue;
    }
    std::vector<double> placed(slots.size());
    double wanted_center = 0.0;
    for (size_t k = 0; k < slots.size(); k++) {
      placed[k] = slots[k].barycenter;
      if (k > 0 && placed[k] < placed[k - 1] + 1.0) {
        placed[k] = placed[k - 1] + 1.0;
      }
      wanted_center += slots[k].barycenter;
    }
    // Pushing apart drifts everything one way; recenter on where the nodes
    // wanted to be.
    double shift = wanted_center / slots.size();
    double actual_center = 0.0;
    for (size_t k = 0; k < placed.size(); k++) {
      actual_center += placed[k];
    }
    shift -= actual_center / placed.size();
    for (size_t k = 0; k < slots.size(); k++) {
      offset[slots[k].node] = placed[k] + shift;
      if (fabs(offset[slots[k].node]) > widest) {
        widest = fabs(offset[slots[k].node]);
      }
    }
  }

  // Into the drawing area, in units where the height is 1 and the width is
  // `aspect`: layers step along the diagonal from bottom-left to top-right,
  // and offsets go at right angles to it (positive toward the top-left).
  const double margin_x = 0.07 * aspect;
  const double margin_y = 0.10;
  double from_x = margin_x;
  double from_y = 1.0 - margin_y;
  double to_x = aspect - margin_x;
  double to_y = margin_y;
  double dx = to_x - from_x;
  double dy = to_y - from_y;
  double length = sqrt(dx * dx + dy * dy);
  double across_x = dy / length;   // perpendicular, pointing up and left
  double across_y = -dx / length;
  double spacing = 0.18;
  if (widest * spacing > 0.42) {
    spacing = 0.42 / widest;
  }

  for (size_t i = 0; i < nodes.size(); i++) {
    double along = (double)nodes[i].layer / last_layer;
    if (along > 1.0) along = 1.0;
    double x = from_x + along * dx + offset[i] * spacing * across_x;
    double y = from_y + along * dy + offset[i] * spacing * across_y;
    float fx = (float)(x / aspect);
    float fy = (float)y;
    if (fx < 0.02f) fx = 0.02f;
    if (fx > 0.98f) fx = 0.98f;
    if (fy < 0.04f) fy = 0.04f;
    if (fy > 0.96f) fy = 0.96f;
    positions[nodes[i].key] = ImVec2(fx * aspect, fy);   // in units of the height
  }
}

bool RouteLayout::places_all(const RouteGraph& graph) const {
  const std::vector<RouteNode>& nodes = graph.get_nodes();
  for (size_t i = 0; i < nodes.size(); i++) {
    if (positions.count(nodes[i].key) == 0) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// The several-endpoint layout
// ---------------------------------------------------------------------------
//
// In two stages.
//
// 1. A starting arrangement with nothing crossed: a tree. Each node hangs
//    from one parent (the node before it with the most flows), "here" at the
//    bottom, children side by side above their parent, each subtree as wide
//    as its labels need. Which side of a split each branch goes on follows
//    one order of the endpoints - chosen by trying the orders and keeping
//    the one whose tree has the fewest crossing links (the links the tree
//    doesn't contain - a router two branches share - can still cross), then
//    the shortest. Physics can't untangle a tangle, so it needs this start.
//
// 2. Physics, with everything free to move. Links pull like springs;
//    endpoints and "here" push each other away hard, which spreads the map
//    out; everything else pushes away at short range; nodes and labels are
//    hard boxes that may not overlap; and links - as wide as their bundle
//    of stripes - push away the nodes and labels they don't belong to. A
//    weak pull back toward the start fades as it goes, and a weak upward
//    nudge tends to keep "here" at the bottom. Chains of three or more
//    routers with no branches stay rigid columns, which read best. At the
//    end, anything still overlapping gets a few hundred more rounds of
//    pushing on its own.
//
// Heights aren't hop counts: a node goes wherever the picture is cleanest.
// The map can come out bigger than the window; RouteView lets you drag and
// zoom it.

// Do segments a-b and c-d cross (properly, not just touch)?
static bool segments_cross(double ax, double ay, double bx, double by, double cx, double cy,
                           double dx, double dy) {
  double d1 = (bx - ax) * (cy - ay) - (by - ay) * (cx - ax);
  double d2 = (bx - ax) * (dy - ay) - (by - ay) * (dx - ax);
  double d3 = (dx - cx) * (ay - cy) - (dy - cy) * (ax - cx);
  double d4 = (dx - cx) * (by - cy) - (dy - cy) * (bx - cx);
  return ((d1 > 0) != (d2 > 0)) && ((d3 > 0) != (d4 > 0)) && d1 != 0 && d2 != 0 && d3 != 0 &&
         d4 != 0;
}

// How tangled a set of positions is: crossings count most; length breaks
// ties (and penalizes branches that double back).
static double layout_score(const std::vector<RouteEdge>& edges, const std::vector<double>& x,
                           const std::vector<double>& y) {
  int crossings = 0;
  double length = 0.0;
  for (size_t a = 0; a < edges.size(); a++) {
    const RouteEdge& e = edges[a];
    length += sqrt((x[e.to] - x[e.from]) * (x[e.to] - x[e.from]) +
                   (y[e.to] - y[e.from]) * (y[e.to] - y[e.from]));
    for (size_t b = a + 1; b < edges.size(); b++) {
      const RouteEdge& f = edges[b];
      if (e.from == f.from || e.from == f.to || e.to == f.from || e.to == f.to) {
        continue;
      }
      if (segments_cross(x[e.from], y[e.from], x[e.to], y[e.to], x[f.from], y[f.from], x[f.to],
                         y[f.to])) {
        crossings++;
      }
    }
  }
  return crossings + 0.2 * length;
}

// Everything the tree arrangement needs that doesn't depend on the order.
struct TreeInput {
  const std::vector<RouteNode>* nodes;
  std::vector<int> depth;                   // links from "here"
  std::vector<std::vector<int> > children;  // in the tree
  std::vector<uint64_t> endpoints_below;    // endpoints using the node or anything above it
  std::vector<double> width;                // a node's own box: dot plus label, plus a gap
  std::vector<double> row_height;           // per depth: the tallest label in that row, plus a gap
  int root;
};

// The lowest position in `order` of any endpoint in `mask`.
static int order_rank(uint64_t mask, const std::vector<int>& order) {
  for (size_t k = 0; k < order.size(); k++) {
    if (order[k] < 64 && (mask & ((uint64_t)1 << order[k])) != 0) {
      return (int)k;
    }
  }
  return (int)order.size();
}

// Width of each subtree, children sorted by the order.
static double subtree_width(const TreeInput& input, int node, const std::vector<int>& order,
                            std::vector<std::vector<int> >* sorted, std::vector<double>* widths) {
  std::vector<int> kids = input.children[node];
  // Sort by rank, then key: the same order every time.
  for (size_t a = 0; a < kids.size(); a++) {
    for (size_t b = a + 1; b < kids.size(); b++) {
      int rank_a = order_rank(input.endpoints_below[kids[a]], order);
      int rank_b = order_rank(input.endpoints_below[kids[b]], order);
      if (rank_b < rank_a ||
          (rank_b == rank_a && (*input.nodes)[kids[b]].key < (*input.nodes)[kids[a]].key)) {
        std::swap(kids[a], kids[b]);
      }
    }
  }
  (*sorted)[node] = kids;
  double total = 0.0;
  for (size_t k = 0; k < kids.size(); k++) {
    total += subtree_width(input, kids[k], order, sorted, widths);
  }
  double own = input.width[node];
  (*widths)[node] = total > own ? total : own;
  return (*widths)[node];
}

static void place_subtree(const TreeInput& input, int node, double left,
                          const std::vector<std::vector<int> >& sorted,
                          const std::vector<double>& widths, const std::vector<double>& row_y,
                          std::vector<double>* x, std::vector<double>* y) {
  const std::vector<int>& kids = sorted[node];
  double at = left;
  for (size_t k = 0; k < kids.size(); k++) {
    place_subtree(input, kids[k], at, sorted, widths, row_y, x, y);
    at += widths[kids[k]];
  }
  // Over its children: straight under a single child (so chains run
  // straight up), centred over several. A leaf at the left of its space.
  if (kids.empty()) {
    (*x)[node] = left;
  } else if (kids.size() == 1) {
    (*x)[node] = (*x)[kids[0]];
  } else {
    (*x)[node] = ((*x)[kids.front()] + (*x)[kids.back()]) / 2.0;
  }
  (*y)[node] = row_y[input.depth[node]];
}

static void tree_positions(const TreeInput& input, const std::vector<int>& order,
                           std::vector<double>* x, std::vector<double>* y) {
  size_t count = input.nodes->size();
  std::vector<std::vector<int> > sorted(count);
  std::vector<double> widths(count, 0.0);
  subtree_width(input, input.root, order, &sorted, &widths);
  // Rows go up from "here" at y = 0 (y is down, so up is negative).
  std::vector<double> row_y(input.row_height.size(), 0.0);
  for (size_t d = 1; d < row_y.size(); d++) {
    row_y[d] = row_y[d - 1] - input.row_height[d - 1];
  }
  x->assign(count, 0.0);
  y->assign(count, 0.0);
  place_subtree(input, input.root, 0.0, sorted, widths, row_y, x, y);
}

// A rigid piece for the physics: one node, or a stacked chain of them.
struct Body {
  std::vector<int> members;        // node indexes
  std::vector<double> offset_x;    // each member's position relative to the body's
  std::vector<double> offset_y;
  double x;                        // the body's position (= its first member's)
  double y;
  double home_x;                   // where the tree put it
  double home_y;
  double min_x;                    // the box it covers, relative to (x, y)
  double max_x;
  double min_y;
  double max_y;
  bool fixed;
  bool important;                  // "here" or an endpoint: pushes the others far away
};

void RouteLayout::compute_multi(const RouteGraph& graph, const std::vector<ImVec2>& label_sizes,
                                float dot_radius, const std::vector<float>& edge_widths) {
  positions.clear();
  const std::vector<RouteNode>& nodes = graph.get_nodes();
  const std::vector<RouteEdge>& edges = graph.get_edges();
  int endpoint_count = graph.get_endpoint_count();
  size_t node_count = nodes.size();
  if (node_count == 0) {
    return;
  }
  const double LABEL_GAP = 0.5 * dot_radius;
  const double COLUMN_GAP = 3.0 * dot_radius;

  TreeInput input;
  input.nodes = &nodes;
  input.root = 0;
  for (size_t i = 0; i < node_count; i++) {
    if (nodes[i].kind == NODE_HERE) {
      input.root = (int)i;
    }
  }

  // Depth (links from "here", breadth first) and each node's parent: the
  // node one link back carrying the most flows.
  input.depth.assign(node_count, -1);
  std::vector<int> parent(node_count, -1);
  std::vector<int> queue(1, input.root);
  input.depth[input.root] = 0;
  for (size_t q = 0; q < queue.size(); q++) {
    int from = queue[q];
    for (size_t e = 0; e < edges.size(); e++) {
      if (edges[e].from == from && input.depth[edges[e].to] < 0) {
        input.depth[edges[e].to] = input.depth[from] + 1;
        queue.push_back(edges[e].to);
      }
    }
  }
  for (size_t i = 0; i < node_count; i++) {
    if ((int)i == input.root) {
      continue;
    }
    if (input.depth[i] < 0) {
      input.depth[i] = 1;   // not linked from "here" (shouldn't happen): hang it off "here"
      parent[i] = input.root;
      continue;
    }
    int best = -1;
    int best_flows = -1;
    for (size_t e = 0; e < edges.size(); e++) {
      if (edges[e].to != (int)i || input.depth[edges[e].from] != input.depth[i] - 1) {
        continue;
      }
      int flows = 0;
      for (size_t k = 0; k < edges[e].flows.size(); k++) {
        FlowMask mask = edges[e].flows[k];
        while (mask != 0) {
          mask &= mask - 1;
          flows++;
        }
      }
      if (flows > best_flows ||
          (flows == best_flows && nodes[edges[e].from].key < nodes[best].key)) {
        best_flows = flows;
        best = edges[e].from;
      }
    }
    parent[i] = best >= 0 ? best : input.root;
  }
  input.children.assign(node_count, std::vector<int>());
  for (size_t i = 0; i < node_count; i++) {
    if (parent[i] >= 0) {
      input.children[parent[i]].push_back((int)i);
    }
  }

  // Which endpoints each subtree leads to, deepest first.
  input.endpoints_below.assign(node_count, 0);
  for (size_t i = 0; i < node_count; i++) {
    for (int e = 0; e < endpoint_count && e < 64; e++) {
      if (nodes[i].uses[e].flows != 0 || (nodes[i].target_of & ((uint64_t)1 << e)) != 0) {
        input.endpoints_below[i] |= (uint64_t)1 << e;
      }
    }
  }
  std::vector<int> by_depth = queue;
  for (size_t i = 0; i < node_count; i++) {
    if (std::find(by_depth.begin(), by_depth.end(), (int)i) == by_depth.end()) {
      by_depth.push_back((int)i);
    }
  }
  for (size_t k = by_depth.size(); k > 0; k--) {
    int node = by_depth[k - 1];
    if (parent[node] >= 0) {
      input.endpoints_below[parent[node]] |= input.endpoints_below[node];
    }
  }

  // Sizes: each node's own width (dot, label, gap to the next column) and
  // each row's height (its tallest label).
  int deepest = 0;
  for (size_t i = 0; i < node_count; i++) {
    if (input.depth[i] > deepest) {
      deepest = input.depth[i];
    }
  }
  input.width.assign(node_count, 0.0);
  input.row_height.assign(deepest + 1, 2.0 * dot_radius);
  for (size_t i = 0; i < node_count; i++) {
    ImVec2 size = i < label_sizes.size() ? label_sizes[i] : ImVec2(0, 0);
    input.width[i] = dot_radius + LABEL_GAP + size.x + COLUMN_GAP;
    double height = LABEL_GAP + size.y + 2.0 * dot_radius;
    if (height > input.row_height[input.depth[i]]) {
      input.row_height[input.depth[i]] = height;
    }
  }

  // ---- Stage 1: the order of the endpoints. Every order of up to 6 (720)
  // is tried; beyond that, neighbour swaps from the natural order while
  // they help. ----
  std::vector<int> with_data;
  for (int e = 0; e < endpoint_count; e++) {
    if (!graph.get_spine(e).empty()) {
      with_data.push_back(e);
    }
  }
  std::vector<double> x;
  std::vector<double> y;
  std::vector<int> best_order = with_data;
  double best_score = 1e300;
  if (with_data.size() <= 6) {
    std::vector<int> order = with_data;
    do {
      tree_positions(input, order, &x, &y);
      double score = layout_score(edges, x, y);
      if (score < best_score) {
        best_score = score;
        best_order = order;
      }
    } while (std::next_permutation(order.begin(), order.end()));
  } else {
    tree_positions(input, best_order, &x, &y);
    best_score = layout_score(edges, x, y);
    bool improved = true;
    while (improved) {
      improved = false;
      for (size_t k = 0; k + 1 < best_order.size(); k++) {
        std::vector<int> trial = best_order;
        std::swap(trial[k], trial[k + 1]);
        tree_positions(input, trial, &x, &y);
        double score = layout_score(edges, x, y);
        if (score < best_score - 1e-9) {
          best_score = score;
          best_order = trial;
          improved = true;
        }
      }
    }
  }
  tree_positions(input, best_order, &x, &y);

  // ---- Stage 2: physics. ----
  // Chains: one way in, one way out, not "here" or a target - three or
  // more in a row become one rigid column.
  std::vector<int> in_degree(node_count, 0);
  std::vector<int> out_degree(node_count, 0);
  std::vector<int> next(node_count, -1);
  for (size_t e = 0; e < edges.size(); e++) {
    in_degree[edges[e].to]++;
    out_degree[edges[e].from]++;
    next[edges[e].from] = edges[e].to;
  }
  std::vector<bool> chainable(node_count, false);
  for (size_t i = 0; i < node_count; i++) {
    chainable[i] = nodes[i].kind != NODE_HERE && nodes[i].target_of == 0 && in_degree[i] == 1 &&
                   out_degree[i] == 1;
  }
  std::vector<Body> bodies;
  std::vector<int> body_of(node_count, -1);
  // Two passes: the chains first (found from where they start), then every
  // node left over on its own.
  for (int pass = 0; pass < 2; pass++) {
    for (size_t i = 0; i < node_count; i++) {
      if (body_of[i] >= 0) {
        continue;
      }
      std::vector<int> chain;
      if (pass == 0) {
        if (!chainable[i]) {
          continue;
        }
        int previous = -1;
        for (size_t e = 0; e < edges.size(); e++) {
          if (edges[e].to == (int)i) {
            previous = edges[e].from;
          }
        }
        if (previous >= 0 && chainable[previous]) {
          continue;   // not the start
        }
        int at = (int)i;
        while (at >= 0 && chainable[at] && body_of[at] < 0) {
          chain.push_back(at);
          at = next[at];
        }
        // A target that ends the chain, and nothing else leads to, joins it.
        if (at >= 0 && nodes[at].target_of != 0 && in_degree[at] == 1 && out_degree[at] == 0 &&
            body_of[at] < 0) {
          chain.push_back(at);
        }
        if (chain.size() < 3) {
          continue;
        }
      } else {
        chain.push_back((int)i);
      }
      Body body;
      body.fixed = nodes[chain[0]].kind == NODE_HERE;
      body.important = false;
      for (size_t k = 0; k < chain.size(); k++) {
        if (nodes[chain[k]].kind == NODE_HERE || nodes[chain[k]].target_of != 0) {
          body.important = true;
        }
      }
      body.x = body.home_x = x[chain[0]];
      body.y = body.home_y = y[chain[0]];
      body.min_x = -dot_radius;
      body.max_x = dot_radius;
      body.min_y = 1e9;
      body.max_y = -1e9;
      for (size_t k = 0; k < chain.size(); k++) {
        int member = chain[k];
        double ox = x[member] - body.x;
        double oy = y[member] - body.y;
        if (chain.size() > 1) {
          // A column: straight up (or down) from the first, a row apart.
          ox = 0.0;
        }
        body.members.push_back(member);
        body.offset_x.push_back(ox);
        body.offset_y.push_back(oy);
        ImVec2 size = member < (int)label_sizes.size() ? label_sizes[member] : ImVec2(0, 0);
        double left = ox - dot_radius;
        double right = ox + dot_radius + LABEL_GAP + size.x;
        double top = oy - dot_radius;
        double bottom = oy + (size.y > 0 ? LABEL_GAP + size.y : dot_radius);
        if (left < body.min_x) body.min_x = left;
        if (right > body.max_x) body.max_x = right;
        if (top < body.min_y) body.min_y = top;
        if (bottom > body.max_y) body.max_y = bottom;
      }
      int index = (int)bodies.size();
      for (size_t k = 0; k < chain.size(); k++) {
        body_of[chain[k]] = index;
      }
      bodies.push_back(body);
    }
  }
  std::vector<double> member_x(node_count, 0.0);
  std::vector<double> member_y(node_count, 0.0);
  for (size_t b = 0; b < bodies.size(); b++) {
    for (size_t k = 0; k < bodies[b].members.size(); k++) {
      member_x[bodies[b].members[k]] = bodies[b].offset_x[k];
      member_y[bodies[b].members[k]] = bodies[b].offset_y[k];
    }
  }
  std::vector<double> half_width(edges.size(), 0.0);
  for (size_t e = 0; e < edges.size(); e++) {
    half_width[e] = e < edge_widths.size() ? edge_widths[e] / 2.0 : 0.0;
  }

  // The typical row: links like to be about this long.
  double typical_row = 0.0;
  for (size_t d = 0; d < input.row_height.size(); d++) {
    typical_row += input.row_height[d];
  }
  typical_row /= input.row_height.size();
  const double SPRING_LENGTH = typical_row * 1.2;
  const double SPRING = 0.06;
  const double FAR_PUSH = 0.0006 * typical_row / 0.08;   // endpoints and "here" spreading apart
  const double NEAR_RANGE = typical_row * 1.5;
  const double NEAR_PUSH = 0.03;
  const double UPWARD = 0.0004;
  const double PADDING = dot_radius;
  size_t body_count = bodies.size();
  std::vector<double> force_x(body_count);
  std::vector<double> force_y(body_count);

  const int MAIN_STEPS = 400;
  const int CLEANUP_STEPS = 300;
  for (int step = 0; step < MAIN_STEPS + CLEANUP_STEPS; step++) {
    bool cleanup = step >= MAIN_STEPS;
    double progress = (double)step / MAIN_STEPS;
    double home = cleanup ? 0.0 : 0.06 * (1.0 - progress) + 0.004;
    for (size_t b = 0; b < body_count; b++) {
      force_x[b] = home * (bodies[b].home_x - bodies[b].x);
      force_y[b] = home * (bodies[b].home_y - bodies[b].y) - (cleanup ? 0.0 : UPWARD);
    }
    // Where each body's box is, this step.
    #define BODY_LEFT(b) (bodies[b].x + bodies[b].min_x)
    #define BODY_RIGHT(b) (bodies[b].x + bodies[b].max_x)
    #define BODY_TOP(b) (bodies[b].y + bodies[b].min_y)
    #define BODY_BOTTOM(b) (bodies[b].y + bodies[b].max_y)

    if (!cleanup) {
      // Links pull toward a comfortable length.
      for (size_t e = 0; e < edges.size(); e++) {
        int a = body_of[edges[e].from];
        int b = body_of[edges[e].to];
        if (a == b) {
          continue;
        }
        double ax = bodies[a].x + member_x[edges[e].from];
        double ay = bodies[a].y + member_y[edges[e].from];
        double bx = bodies[b].x + member_x[edges[e].to];
        double by = bodies[b].y + member_y[edges[e].to];
        double dx = bx - ax;
        double dy = by - ay;
        double distance = sqrt(dx * dx + dy * dy);
        if (distance < 1e-9) {
          continue;
        }
        double pull = SPRING * (distance - SPRING_LENGTH);
        force_x[a] += pull * dx / distance;
        force_y[a] += pull * dy / distance;
        force_x[b] -= pull * dx / distance;
        force_y[b] -= pull * dy / distance;
      }
      // Endpoints and "here" push each other far apart; everything pushes
      // its near neighbours away.
      for (size_t a = 0; a < body_count; a++) {
        for (size_t b = a + 1; b < body_count; b++) {
          double ax = (BODY_LEFT(a) + BODY_RIGHT(a)) / 2;
          double ay = (BODY_TOP(a) + BODY_BOTTOM(a)) / 2;
          double bx = (BODY_LEFT(b) + BODY_RIGHT(b)) / 2;
          double by = (BODY_TOP(b) + BODY_BOTTOM(b)) / 2;
          double dx = bx - ax;
          double dy = by - ay;
          double distance = sqrt(dx * dx + dy * dy);
          if (distance < 1e-6) {
            dx = nodes[bodies[a].members[0]].key < nodes[bodies[b].members[0]].key ? 1.0 : -1.0;
            dy = 0.0;
            distance = 1e-6;
          }
          double push = 0.0;
          if (bodies[a].important && bodies[b].important) {
            push += FAR_PUSH / (distance * distance + 0.01);
          }
          if (distance < NEAR_RANGE) {
            push += NEAR_PUSH * (NEAR_RANGE - distance);
          }
          if (push > 0.0) {
            force_x[a] -= push * dx / distance;
            force_y[a] -= push * dy / distance;
            force_x[b] += push * dx / distance;
            force_y[b] += push * dy / distance;
          }
        }
      }
    }

    // Boxes may not overlap: push apart along whichever axis they overlap
    // least.
    for (size_t a = 0; a < body_count; a++) {
      for (size_t b = a + 1; b < body_count; b++) {
        double overlap_x = std::min(BODY_RIGHT(a), BODY_RIGHT(b)) -
                           std::max(BODY_LEFT(a), BODY_LEFT(b)) + PADDING;
        double overlap_y = std::min(BODY_BOTTOM(a), BODY_BOTTOM(b)) -
                           std::max(BODY_TOP(a), BODY_TOP(b)) + PADDING;
        if (overlap_x <= 0 || overlap_y <= 0) {
          continue;
        }
        double centre_dx = (BODY_LEFT(b) + BODY_RIGHT(b)) / 2 - (BODY_LEFT(a) + BODY_RIGHT(a)) / 2;
        double centre_dy = (BODY_TOP(b) + BODY_BOTTOM(b)) / 2 - (BODY_TOP(a) + BODY_BOTTOM(a)) / 2;
        double push_x = 0.0;
        double push_y = 0.0;
        if (overlap_x < overlap_y) {
          push_x = (centre_dx >= 0 ? 1.0 : -1.0) * overlap_x * 0.5;
        } else {
          push_y = (centre_dy >= 0 ? 1.0 : -1.0) * overlap_y * 0.5;
        }
        force_x[a] -= push_x;
        force_y[a] -= push_y;
        force_x[b] += push_x;
        force_y[b] += push_y;
      }
    }

    // Links - as wide as their bundle - push away the boxes they don't
    // belong to: a link through a box shoves it sideways.
    for (size_t b = 0; b < body_count; b++) {
      double left = BODY_LEFT(b);
      double right = BODY_RIGHT(b);
      double top = BODY_TOP(b);
      double bottom = BODY_BOTTOM(b);
      double centre_x = (left + right) / 2;
      double centre_y = (top + bottom) / 2;
      for (size_t e = 0; e < edges.size(); e++) {
        int from = edges[e].from;
        int to = edges[e].to;
        if (body_of[from] == (int)b || body_of[to] == (int)b) {
          continue;
        }
        double grow = half_width[e] + PADDING / 2;
        double ax = bodies[body_of[from]].x + member_x[from];
        double ay = bodies[body_of[from]].y + member_y[from];
        double bx = bodies[body_of[to]].x + member_x[to];
        double by = bodies[body_of[to]].y + member_y[to];
        // Clip the link to the box, grown by the link's half-width
        // (Liang-Barsky); if anything's left, they touch.
        double t0 = 0.0;
        double t1 = 1.0;
        double dx = bx - ax;
        double dy = by - ay;
        double p[4] = {-dx, dx, -dy, dy};
        double q[4] = {ax - (left - grow), (right + grow) - ax, ay - (top - grow),
                       (bottom + grow) - ay};
        bool touching = true;
        for (int k = 0; k < 4 && touching; k++) {
          if (p[k] == 0.0) {
            touching = q[k] >= 0.0;
          } else {
            double t = q[k] / p[k];
            if (p[k] < 0.0) {
              if (t > t1) touching = false;
              else if (t > t0) t0 = t;
            } else {
              if (t < t0) touching = false;
              else if (t < t1) t1 = t;
            }
          }
        }
        if (!touching) {
          continue;
        }
        double length = sqrt(dx * dx + dy * dy);
        if (length < 1e-9) {
          continue;
        }
        double nx = -dy / length;
        double ny = dx / length;
        double side = (centre_x - ax) * nx + (centre_y - ay) * ny;
        if (side < 0) {
          nx = -nx;
          ny = -ny;
        }
        double strength = typical_row * 0.08;
        force_x[b] += nx * strength;
        force_y[b] += ny * strength;
        // The link's ends get the opposite push, so both make room.
        if (!bodies[body_of[from]].fixed) {
          force_x[body_of[from]] -= nx * strength * 0.5;
          force_y[body_of[from]] -= ny * strength * 0.5;
        }
        if (!bodies[body_of[to]].fixed) {
          force_x[body_of[to]] -= nx * strength * 0.5;
          force_y[body_of[to]] -= ny * strength * 0.5;
        }
      }
    }
    #undef BODY_LEFT
    #undef BODY_RIGHT
    #undef BODY_TOP
    #undef BODY_BOTTOM

    // Move, a little less each step.
    double limit = typical_row * (cleanup ? 0.15 : 0.4 * (1.0 - 0.8 * progress));
    for (size_t b = 0; b < body_count; b++) {
      if (bodies[b].fixed) {
        continue;
      }
      double move_x = force_x[b];
      double move_y = force_y[b];
      double size = sqrt(move_x * move_x + move_y * move_y);
      if (size > limit) {
        move_x *= limit / size;
        move_y *= limit / size;
      }
      bodies[b].x += move_x;
      bodies[b].y += move_y;
    }
  }

  // Out, with the map's top-left corner (including labels) at (0, 0).
  double min_x = 1e9;
  double min_y = 1e9;
  for (size_t b = 0; b < body_count; b++) {
    min_x = std::min(min_x, bodies[b].x + bodies[b].min_x);
    min_y = std::min(min_y, bodies[b].y + bodies[b].min_y);
  }
  for (size_t i = 0; i < node_count; i++) {
    const Body& body = bodies[body_of[i]];
    positions[nodes[i].key] =
        ImVec2((float)(body.x + member_x[i] - min_x), (float)(body.y + member_y[i] - min_y));
  }
}
