// route_view.h - draws the route graph, and handles the mouse on it.
//
// One view, two ways in: a row's route button opens it showing just that
// host ("endpoint"); the R key opens it showing all of them. Checkboxes add
// and remove endpoints either way: under the title with one endpoint, as the
// time strip's lane names with several. The last one can't be removed. The graph always shows
// the routes during the time window the rows are showing, so zooming or
// dragging back in time shows the routes as they were then.
//
// With ONE endpoint, its heatmap row sits short at the top, and the graph
// runs from "here" at the bottom left to the target at the top right.
//
// With SEVERAL, the graph is laid out as a tree that physics then spreads
// out (route_graph.cpp, above compute_multi), and takes nearly the whole
// window. It can come out bigger than the window: drag it to move it, scroll
// to zoom, "Fit" to fit. Above it, a thin time strip has one lane per
// endpoint: shaded where there's data, red bars for loss, and a tick
// wherever one of that endpoint's paths changed - the moments worth
// scrubbing to. Drag and scroll the strip as you would a heatmap. Each
// endpoint has a color; a link used by several endpoints is drawn as
// parallel stripes, one per endpoint, each as thick as that endpoint's share
// of the traffic over it, like subway lines sharing a track.
//
// Either way, every router appears once, labeled with its address and,
// below that, the domain that owns it (from reverse DNS). Hover over a
// router, its label, or a link for details: round-trip times, how often it
// answers, which flows go through it, and the share of each endpoint's
// traffic. Click one to select the flows that use it - they light up here
// AND in the heatmaps; click empty space to clear.
//
// The layout stays put while the graph keeps the same nodes. When a router
// (or silent hop) turns up that it doesn't place, it's laid out again - so
// the map rearranges itself now and then, mostly in the first minute.

#ifndef PINGEM_ROUTE_VIEW_H
#define PINGEM_ROUTE_VIEW_H

#include "public_suffix.h"
#include "reverse_dns.h"
#include "route_graph.h"
#include "route_store.h"
#include "tabulation.h"

#include "row_view.h"   // CELL_WIDTH

#include "../third_party/imgui/imgui.h"

#include <string>
#include <vector>

// One endpoint being shown.
struct RouteViewEndpoint {
  int target_id;
  std::string name;
  std::string address;       // the target's address (for finding our own, under "here")
  const RouteStore* store;
  int flow_count;
  ImU32 color;
  FlowMask selection;        // in: the row's selection; out: changed by clicks
  FlowMask hover_flows;      // flows to light up because the mouse is on them elsewhere
};

// The larger font for "here", targets' names, and the "*" and "?" of silent
// hops. NULL (the default) scales the normal font instead.
void set_route_view_big_font(ImFont* font);

// A color for each endpoint, chosen to stay distinct with red-green color
// blindness (after Okabe and Ito), and away from the loss bars' red.
ImU32 endpoint_color(int index);

class RouteView {
public:
  RouteView();

  // Call when the view opens or the set of endpoints changes: forgets the
  // layout.
  void reset();

  // Once per frame while open. Draws the graph in [area_min, area_max] and
  // handles the mouse there. Selections in *endpoints are updated by clicks.
  void draw(ImDrawList* draw_list, ImVec2 area_min, ImVec2 area_max,
            std::vector<RouteViewEndpoint>* endpoints, double window_start, double window_end,
            const std::string& title, ReverseDns* names, const PublicSuffixList& suffixes,
            bool mouse_is_ours, double now);

  // Which endpoints (bit = index in the endpoints list) the thing under the
  // mouse belongs to, as of the last draw(). The time strip lights their
  // lanes.
  uint64_t get_hovered_endpoints() const;

private:
  void describe_node(const RouteNode& node, const std::vector<RouteViewEndpoint>& endpoints,
                     ReverseDns* names, const PublicSuffixList& suffixes, std::string* out) const;
  void describe_edge(const RouteEdge& edge, const std::vector<RouteViewEndpoint>& endpoints,
                     std::string* out) const;

  RouteGraph graph;
  RouteLayout layout;
  bool have_layout;
  // This machine's address(es) for reaching the endpoints - shown under
  // "here". Looked up again every half minute, in case DHCP changes them.
  void update_local_addresses(const std::vector<RouteViewEndpoint>& endpoints, double now);
  std::vector<std::string> local_addresses;
  std::map<std::string, std::string> local_by_target;   // target address -> ours
  double local_addresses_time;

  void center_view(float map_width, float map_height, float view_width, float view_height,
                   float top_room);

  uint64_t hovered_endpoints;
  std::vector<int> shown_ids;   // the endpoints the layout was made for

  // Several endpoints: the map can be bigger than the window, so it can be
  // zoomed and dragged. screen = area corner + (map pixel - pan) * zoom.
  float zoom;
  ImVec2 pan;
  bool view_touched;            // the user has zoomed or dragged since the layout was made
  bool panning;                 // the left button went down on empty map
  bool pan_moved;               // ...and the mouse has moved since (a drag, not a click)
  ImVec2 pan_mouse;             // where the button went down
  ImVec2 pan_start;             // the pan then
};

// One lane of the time strip.
struct RouteLane {
  ImU32 color;
  const RouteStore* store;
  const Tabulation* tabulation;   // the endpoint's pings, tabulated for the strip's window
  bool lit;                       // the mouse is on something of this endpoint's
  bool on_map;                    // shown on the map (if not, the lane is dimmed)
};

// The time strip above the all-routes graph: one lane per target, drawn
// in [box_min, box_max]; the lanes' cells start at inset_x, one per column of
// `window`, CELL_WIDTH wide. Clock-time grid lines and labels as on the
// heatmaps; a crosshair line at crosshair_x (0..1 across the cells) if
// crosshair_visible. The lanes' names are their checkboxes, drawn by the
// caller.
void draw_route_lanes(ImDrawList* draw_list, ImVec2 box_min, ImVec2 box_max, float inset_x,
                      float lane_height, const std::vector<RouteLane>& lanes,
                      const ViewWindow& window, double now, bool crosshair_visible,
                      double crosshair_x);

#endif
