#include "route_view.h"

#include "row_view.h"   // draw_outlined_text, format_ms

#include <algorithm>
#include <math.h>
#include <stdio.h>

// While the view is this new (seconds), a growing graph is simply laid out
// again: the first probes are still arriving, and asking every second would
// be silly.
static const double SETTLING_SECONDS = 15.0;

static const float NODE_RADIUS = 6.0f;

static const ImU32 COLOR_BACKGROUND = IM_COL32(0, 0, 0, 255);
static const ImU32 COLOR_BORDER = IM_COL32(128, 128, 128, 255);
static const ImU32 COLOR_EDGE = IM_COL32(120, 130, 170, 255);
static const ImU32 COLOR_EDGE_DIM = IM_COL32(55, 58, 70, 255);
static const ImU32 COLOR_EDGE_LIT = IM_COL32(255, 225, 110, 255);
static const ImU32 COLOR_NODE = IM_COL32(200, 200, 215, 255);
static const ImU32 COLOR_NODE_DIM = IM_COL32(80, 80, 90, 255);
static const ImU32 COLOR_NODE_LIT = IM_COL32(255, 225, 110, 255);
static const ImU32 COLOR_HERE = IM_COL32(110, 200, 110, 255);
static const ImU32 COLOR_TARGET = IM_COL32(120, 170, 255, 255);
static const ImU32 COLOR_SILENT = IM_COL32(90, 90, 90, 255);
static const ImU32 COLOR_REFUSED = IM_COL32(230, 60, 60, 255);
static const ImU32 COLOR_TEXT = IM_COL32(255, 255, 255, 255);
static const ImU32 COLOR_TEXT_DIM = IM_COL32(140, 140, 140, 255);
static const ImU32 COLOR_OWNER = IM_COL32(160, 200, 255, 255);
static const ImU32 COLOR_LOSS = IM_COL32(150, 0, 0, 255);
static const ImU32 COLOR_CROSSHAIR = IM_COL32(255, 0, 0, 255);

ImU32 endpoint_color(int index) {
  static const ImU32 PALETTE[] = {
      IM_COL32(86, 180, 233, 255),    // sky blue
      IM_COL32(230, 159, 0, 255),     // orange
      IM_COL32(204, 121, 167, 255),   // reddish purple
      IM_COL32(240, 228, 66, 255),    // yellow
      IM_COL32(60, 140, 230, 255),    // blue
      IM_COL32(0, 190, 160, 255),     // bluish green
      IM_COL32(220, 220, 220, 255),   // light gray
      IM_COL32(200, 150, 100, 255),   // tan
  };
  return PALETTE[index % (int)(sizeof(PALETTE) / sizeof(PALETTE[0]))];
}

// `color` at `brightness` (0..1).
static ImU32 scale_color(ImU32 color, float brightness) {
  int r = (int)(((color >> IM_COL32_R_SHIFT) & 0xff) * brightness);
  int g = (int)(((color >> IM_COL32_G_SHIFT) & 0xff) * brightness);
  int b = (int)(((color >> IM_COL32_B_SHIFT) & 0xff) * brightness);
  return IM_COL32(r, g, b, 255);
}

RouteView::RouteView()
    : have_layout(false),
      opened_at(0.0),
      hovered_endpoints(0),
      zoom(1.0f),
      pan(0, 0),
      view_touched(false),
      panning(false),
      pan_moved(false),
      pan_mouse(0, 0),
      pan_start(0, 0) {
}

void RouteView::center_view(float map_width, float map_height, float view_width,
                            float view_height, float top_room) {
  // Centred both ways; if it's bigger than the view, its top-left corner
  // shows first.
  float shown_width = view_width / zoom;
  float shown_height = view_height / zoom;
  pan.x = map_width < shown_width ? (map_width - shown_width) / 2.0f : 0.0f;
  pan.y = map_height < shown_height ? (map_height - shown_height) / 2.0f : 0.0f;
  pan.y -= top_room / zoom;
}

uint64_t RouteView::get_hovered_endpoints() const {
  return hovered_endpoints;
}

void RouteView::reset(double now) {
  have_layout = false;
  view_touched = false;
  panning = false;
  hovered_endpoints = 0;
  opened_at = now;
  layout.positions.clear();
}

// A node's label, worked out before the layout (which needs its size) and
// placed before drawing (so it can be hovered and clicked like its dot).
struct NodeLabel {
  bool shown;
  bool flip;            // right-aligned at `at`: drawn to the left of the node
  ImVec2 at;            // top-left (top-right if flipped), on screen
  ImVec2 size;          // the whole label, at 100% zoom
  // "here" and targets get a title: bigger text in a colored box.
  std::string title;
  ImU32 title_color;
  // Then smaller lines: address, owner domain; or a run's "x5".
  std::vector<std::string> lines;
  std::vector<ImU32> colors;
};

static ImFont* big_font = NULL;

void set_route_view_big_font(ImFont* font) {
  big_font = font;
}

static float big_size() {
  return big_font != NULL ? big_font->FontSize : ImGui::GetFontSize() * 1.35f;
}

static ImVec2 big_text_size(const char* text) {
  ImFont* font = big_font != NULL ? big_font : ImGui::GetFont();
  return font->CalcTextSizeA(big_size(), 1e9f, 0.0f, text);
}

// The padding inside a title box.
static const float BOX_PAD = 3.0f;

// Text at `scale` times its normal size, with a black outline: the map's
// labels zoom with the map.
static void scaled_text(ImDrawList* draw_list, ImVec2 position, ImU32 color, const char* text,
                        float scale, bool align_right) {
  ImFont* font = ImGui::GetFont();
  float size = ImGui::GetFontSize() * scale;
  if (align_right) {
    position.x -= font->CalcTextSizeA(size, 1e9f, 0.0f, text).x;
  }
  position.x = floorf(position.x);
  position.y = floorf(position.y);
  const ImU32 outline = IM_COL32(0, 0, 0, 255);
  for (int dy = -1; dy <= 1; dy++) {
    for (int dx = -1; dx <= 1; dx++) {
      if (dx != 0 || dy != 0) {
        draw_list->AddText(font, size, ImVec2(position.x + dx, position.y + dy), outline, text);
      }
    }
  }
  draw_list->AddText(font, size, position, color, text);
}

// Is `point` over the label?
static bool label_contains(const NodeLabel& label, ImVec2 point, float scale) {
  if (!label.shown) {
    return false;
  }
  float width = label.size.x * scale;
  float left = label.flip ? label.at.x - width : label.at.x;
  return point.x >= left - 1 && point.x < left + width + 1 && point.y >= label.at.y &&
         point.y < label.at.y + label.size.y * scale;
}

static void draw_label(ImDrawList* draw_list, const NodeLabel& label, bool dim, float scale,
                       bool backing) {
  float line = ImGui::GetTextLineHeight() * scale;
  float y = label.at.y;
  if (backing) {
    // A dark, see-through backing, so the text reads even where a bundle of
    // links has to pass behind it.
    float width = label.size.x * scale;
    float left = label.flip ? label.at.x - width : label.at.x;
    draw_list->AddRectFilled(ImVec2(left - 2, label.at.y - 1),
                             ImVec2(left + width + 2, label.at.y + label.size.y * scale + 1),
                             IM_COL32(0, 0, 0, 170), 3.0f);
  }
  if (!label.title.empty()) {
    ImVec2 text = big_text_size(label.title.c_str());
    text.x *= scale;
    text.y *= scale;
    float pad = BOX_PAD * scale;
    float box_width = text.x + 2 * pad;
    float left = label.flip ? label.at.x - box_width : label.at.x;
    ImU32 color = dim ? scale_color(label.title_color, 0.4f) : label.title_color;
    draw_list->AddRectFilled(ImVec2(left, y), ImVec2(left + box_width, y + text.y + 2 * pad),
                             IM_COL32(0, 0, 0, 230), 3.0f * scale);
    draw_list->AddRect(ImVec2(left, y), ImVec2(left + box_width, y + text.y + 2 * pad), color,
                       3.0f * scale, 0, 1.5f);
    draw_list->AddText(big_font, big_size() * scale, ImVec2(left + pad, y + pad), color,
                       label.title.c_str());
    y += text.y + 2 * pad + scale;
  }
  for (size_t k = 0; k < label.lines.size(); k++) {
    ImU32 color = dim ? COLOR_TEXT_DIM : label.colors[k];
    scaled_text(draw_list, ImVec2(label.at.x, y), color, label.lines[k].c_str(), scale,
                label.flip);
    y += line;
  }
}

// "x5", or "x4-5" when different flows' runs differ.
static std::string run_length_text(const RouteNode& node) {
  char text[32];
  if (node.run_max <= 1) {
    return std::string();
  }
  if (node.run_min == node.run_max) {
    snprintf(text, sizeof(text), "\xc3\x97%d", node.run_max);
  } else {
    snprintf(text, sizeof(text), "\xc3\x97%d-%d", node.run_min, node.run_max);
  }
  return text;
}

// Between the stripes of a bundle.
static const float STRIPE_GAP = 1.0f;

static int count_flows(FlowMask mask) {
  int count = 0;
  while (mask != 0) {
    mask &= mask - 1;
    count++;
  }
  return count;
}

// Distance from p to the segment a-b.
static float distance_to_segment(ImVec2 p, ImVec2 a, ImVec2 b) {
  float dx = b.x - a.x;
  float dy = b.y - a.y;
  float length2 = dx * dx + dy * dy;
  float t = 0.0f;
  if (length2 > 0.0f) {
    t = ((p.x - a.x) * dx + (p.y - a.y) * dy) / length2;
    if (t < 0.0f) t = 0.0f;
    if (t > 1.0f) t = 1.0f;
  }
  float x = a.x + t * dx - p.x;
  float y = a.y + t * dy - p.y;
  return sqrtf(x * x + y * y);
}

// The name and owner domain for an address, as far as reverse DNS has got.
static void names_for(const std::string& address, ReverseDns* names,
                      const PublicSuffixList& suffixes, std::string* hostname,
                      std::string* owner, bool* looked_up) {
  hostname->clear();
  owner->clear();
  *looked_up = names->lookup(address, hostname);
  if (!hostname->empty()) {
    *owner = suffixes.owner_domain(*hostname);
  }
}

static bool is_target_of(const RouteNode& node, int endpoint) {
  return endpoint < 64 && (node.target_of & ((uint64_t)1 << endpoint)) != 0;
}

void RouteView::describe_node(const RouteNode& node,
                              const std::vector<RouteViewEndpoint>& endpoints, ReverseDns* names,
                              const PublicSuffixList& suffixes, std::string* out) const {
  char line[512];
  std::string text;
  if (node.kind == NODE_HERE) {
    *out = "here: this machine, where every path starts";
    return;
  }
  if (node.kind == NODE_SILENT) {
    int first = node.ttls.empty() ? node.hop : node.ttls.front();
    int last = node.ttls.empty() ? node.hop : node.ttls.back();
    char hops[64];
    if (node.run_max <= 1) {
      snprintf(hops, sizeof(hops), "a hop that never answered (TTL %d)", first);
    } else if (node.run_min == node.run_max) {
      snprintf(hops, sizeof(hops), "%d hops that never answered (TTL %d-%d)", node.run_max, first,
               last);
    } else {
      snprintf(hops, sizeof(hops), "%d-%d hops that never answered (TTL %d-%d)", node.run_min,
               node.run_max, first, last);
    }
    if (node.uncertain) {
      snprintf(line, sizeof(line),
               "? - %s, so far\n"
               "Only a few probes have gone unanswered: it may be a\n"
               "router that never answers, or the probes may just\n"
               "have been lost. It becomes * after %d unanswered\n"
               "probes, or a router as soon as one answers.\n",
               hops, 3);
    } else {
      snprintf(line, sizeof(line),
               "* - %s\n"
               "Many routers never send Time Exceeded, or send\n"
               "only a few a second; that's not a fault.\n",
               hops);
    }
    text = line;
  } else {
    std::string hostname;
    std::string owner;
    bool looked_up;
    names_for(node.address, names, suffixes, &hostname, &owner, &looked_up);
    text = node.address + "\n";
    if (!hostname.empty()) {
      text += hostname + "\n";
    } else {
      text += looked_up ? "(no reverse DNS name)\n" : "(looking up its name...)\n";
    }
    for (size_t e = 0; e < endpoints.size(); e++) {
      if (is_target_of(node, (int)e)) {
        text += "the target " + (endpoints.size() > 1 ? endpoints[e].name + " " : std::string()) +
                "- answered probes with an echo reply\n";
      }
    }
    if (node.refused) {
      snprintf(line, sizeof(line), "REFUSED %d probe%s: ", node.refused_count,
               node.refused_count == 1 ? "" : "s");
      text += line + describe_icmp_error(3, node.refused_code) + "\n";
    }
    if (!node.ttls.empty()) {
      std::string ttls;
      for (size_t i = 0; i < node.ttls.size(); i++) {
        snprintf(line, sizeof(line), "%s%d", i == 0 ? "" : ",", node.ttls[i]);
        ttls += line;
      }
      text += (node.ttls.size() == 1 ? "TTL " : "TTLs ") + ttls + "\n";
    }
    if (!node.rtts.empty()) {
      char low[32];
      char median[32];
      char high[32];
      format_ms(node.rtts.front(), "", low, sizeof(low));
      format_ms(node.rtts[node.rtts.size() / 2], "", median, sizeof(median));
      format_ms(node.rtts.back(), "", high, sizeof(high));
      snprintf(line, sizeof(line), "RTT %s min, %s median, %s max\n", low, median, high);
      text += line;
      // Routers answer Time Exceeded on their slow path, so their RTTs
      // usually run high and jumpy. It's the target's that count.
      if (node.target_of == 0) {
        text += "(a router's own RTT is often slower than traffic through it)\n";
      }
    }
    double asked = node.answered + node.unanswered;
    if (asked > 0) {
      snprintf(line, sizeof(line), "answered %.0f%% of %.0f probes\n",
               100.0 * node.answered / asked, asked);
      text += line;
    }
  }

  // The traffic: for each endpoint whose paths use it, its share over the
  // time shown, and how many flows use it as of their newest probes.
  bool selected = true;
  for (size_t e = 0; e < endpoints.size(); e++) {
    const EndpointUse& use = node.uses[e];
    int flow_count = endpoints[e].flow_count;
    if (endpoints[e].selection != use.flows) {
      selected = false;
    }
    if (use.flows == 0) {
      continue;
    }
    std::string prefix = endpoints.size() > 1 ? "to " + endpoints[e].name + ": " : "";
    std::string indent = endpoints.size() > 1 ? "  " : "";
    snprintf(line, sizeof(line), "%scarries ~%.0f%% of the traffic over the time shown\n",
             prefix.c_str(), 100.0 * use.share);
    text += line;
    snprintf(line, sizeof(line), "%sright now: %d of %d flows\n", indent.c_str(),
             count_flows(use.now_flows), flow_count);
    text += line;
    snprintf(line, sizeof(line), "%sflows %s\n", indent.c_str(),
             describe_flow_mask(use.flows).c_str());
    text += line;
  }
  text += selected ? "click to clear the highlight" : "click to highlight these flows";
  *out = text;
}

void RouteView::describe_edge(const RouteEdge& edge,
                              const std::vector<RouteViewEndpoint>& endpoints,
                              std::string* out) const {
  char line[256];
  std::string text;
  bool selected = true;
  for (size_t e = 0; e < endpoints.size(); e++) {
    FlowMask flows = edge.flows[e];
    if (endpoints[e].selection != flows) {
      selected = false;
    }
    if (flows == 0) {
      continue;
    }
    std::string prefix = endpoints.size() > 1 ? "to " + endpoints[e].name + ": " : "";
    snprintf(line, sizeof(line), "%sflows %s (%d of %d) take this link\n", prefix.c_str(),
             describe_flow_mask(flows).c_str(), count_flows(flows), endpoints[e].flow_count);
    text += line;
  }
  text += selected ? "click to clear the highlight" : "click to highlight these flows";
  *out = text;
}

void RouteView::draw(ImDrawList* draw_list, ImVec2 area_min, ImVec2 area_max,
                     std::vector<RouteViewEndpoint>* endpoint_list, double window_start,
                     double window_end, const std::string& title, ReverseDns* names,
                     const PublicSuffixList& suffixes, bool mouse_is_ours, double now) {
  std::vector<RouteViewEndpoint>& endpoints = *endpoint_list;
  int endpoint_count = (int)endpoints.size();
  bool several = endpoint_count > 1;
  hovered_endpoints = 0;

  draw_list->AddRectFilled(area_min, area_max, COLOR_BACKGROUND);
  draw_list->AddRect(area_min, area_max, COLOR_BORDER);
  float width = area_max.x - area_min.x;
  float height = area_max.y - area_min.y;
  float height_px = height;
  if (width < 50 || height < 50 || endpoint_count == 0) {
    return;
  }

  // A different set of endpoints is a different picture: start afresh.
  std::vector<int> ids;
  for (int e = 0; e < endpoint_count; e++) {
    ids.push_back(endpoints[e].target_id);
  }
  if (ids != shown_ids) {
    shown_ids = ids;
    reset(now);
  }

  std::vector<RouteEndpoint> sources;
  for (int e = 0; e < endpoint_count; e++) {
    RouteEndpoint source;
    source.store = endpoints[e].store;
    source.flow_count = endpoints[e].flow_count;
    sources.push_back(source);
  }
  graph.build_if_needed(sources, window_start, window_end);
  for (int e = 0; e < endpoint_count; e++) {
    endpoints[e].flow_count = graph.get_flow_count(e);
  }
  draw_outlined_text(draw_list, ImVec2(area_min.x + 6, area_min.y + 4), COLOR_TEXT,
                     title.c_str(), false, false);

  if (graph.is_empty()) {
    const char* message = "No route probes answered in this time window yet.";
    if (!several && endpoints[0].flow_count == 0) {
      message = "Routes are found with flows; this target has none (--flows 0).";
    }
    ImVec2 size = ImGui::CalcTextSize(message);
    draw_outlined_text(draw_list,
                       ImVec2(area_min.x + (width - size.x) / 2, area_min.y + height / 2),
                       COLOR_TEXT_DIM, message, false, false);
    return;
  }

  const std::vector<RouteNode>& nodes = graph.get_nodes();
  const std::vector<RouteEdge>& edges = graph.get_edges();

  // What each node's label says - and so how big it is, which the layout
  // needs.
  float base_line = ImGui::GetTextLineHeight();
  std::vector<NodeLabel> labels(nodes.size());
  std::vector<ImVec2> label_sizes(nodes.size(), ImVec2(0, 0));
  for (size_t i = 0; i < nodes.size(); i++) {
    NodeLabel& label = labels[i];
    const RouteNode& node = nodes[i];
    label.shown = false;
    label.flip = false;
    label.title_color = COLOR_TEXT;
    float label_width = 0.0f;
    float pending_width = 0.0f;   // room for an owner domain not looked up yet
    if (node.kind == NODE_HERE) {
      label.title = "here";
      label.title_color = COLOR_HERE;
    } else if (node.kind == NODE_SILENT) {
      std::string run = run_length_text(node);
      if (!run.empty()) {
        label.lines.push_back(run);
        label.colors.push_back(COLOR_TEXT);
      }
    } else {
      for (int e = 0; e < endpoint_count; e++) {
        if (is_target_of(node, e) && label.title.empty()) {
          label.title = endpoints[e].name;
          label.title_color = several ? endpoints[e].color : COLOR_TARGET;
        }
      }
      if (label.title != node.address) {
        label.lines.push_back(node.address);
        label.colors.push_back(COLOR_TEXT);
      }
      std::string hostname;
      std::string owner;
      bool looked_up;
      names_for(node.address, names, suffixes, &hostname, &owner, &looked_up);
      if (!owner.empty()) {
        label.lines.push_back(owner);
        label.colors.push_back(COLOR_OWNER);
      } else if (!looked_up) {
        pending_width = ImGui::CalcTextSize("example.net").x;
      }
    }
    float label_height = 0.0f;
    if (!label.title.empty()) {
      ImVec2 text = big_text_size(label.title.c_str());
      label_width = text.x + 2 * BOX_PAD;
      label_height = text.y + 2 * BOX_PAD + 1;
    }
    for (size_t k = 0; k < label.lines.size(); k++) {
      float w = ImGui::CalcTextSize(label.lines[k].c_str()).x;
      if (w > label_width) {
        label_width = w;
      }
      label_height += base_line;
    }
    label.size = ImVec2(label_width, label_height);
    if (pending_width > label_width) {
      label_width = pending_width;
    }
    if (pending_width > 0.0f) {
      label_height += base_line;
    }
    label.shown = !label.lines.empty() || !label.title.empty();
    label_sizes[i] = ImVec2(label_width / height_px, label_height / height_px);
  }

  // How wide each link is drawn (several endpoints: its bundle of stripes).
  std::vector<float> edge_pixels(edges.size(), 0.0f);
  for (size_t k = 0; k < edges.size(); k++) {
    float total = 0.0f;
    int stripes = 0;
    for (int e = 0; e < endpoint_count; e++) {
      if (edges[k].flows[e] == 0) {
        continue;
      }
      int flow_count = endpoints[e].flow_count > 0 ? endpoints[e].flow_count : 1;
      total += 1.5f + 5.0f * count_flows(edges[k].flows[e]) / flow_count;
      stripes++;
    }
    edge_pixels[k] = total + STRIPE_GAP * (stripes > 0 ? stripes - 1 : 0);
  }

  // Keep the layout, unless it's missing nodes. Then: redo it quietly while
  // the view is new, otherwise offer to. With several endpoints, also the
  // buttons to fit the map in the window or show it at full size.
  bool settling = now - opened_at < SETTLING_SECONDS;
  bool redo = !have_layout || (settling && !layout.places_all(graph));
  bool offer_redo = !redo && !layout.places_all(graph);
  bool fit_pressed = false;
  bool full_pressed = false;
  if (offer_redo || several) {
    ImGui::SetNextWindowPos(ImVec2(area_max.x - 6, area_min.y + 4), 0, ImVec2(1.0f, 0.0f));
    ImGui::SetNextWindowBgAlpha(0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("route_buttons", NULL,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                     ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                     ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove);
    if (offer_redo) {
      if (ImGui::Button("New routes found - redo the layout")) {
        redo = true;
      }
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("The graph has routers the current picture doesn't show.\n"
                          "Nothing moves until you ask, so you don't lose your place.");
      }
      if (several) {
        ImGui::SameLine();
      }
    }
    if (several) {
      if (ImGui::Button("Fit")) {
        fit_pressed = true;
      }
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Shrink the map to fit the window.\n"
                          "Drag the map to move it; scroll over it to zoom.");
      }
      ImGui::SameLine();
      if (ImGui::Button("100%")) {
        full_pressed = true;
      }
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Show the map at full size");
      }
    }
    ImGui::End();
    ImGui::PopStyleVar();
  }
  if (redo) {
    if (several) {
      std::vector<float> edge_widths(edges.size());
      for (size_t k = 0; k < edges.size(); k++) {
        edge_widths[k] = edge_pixels[k] / height_px;
      }
      layout.compute_multi(graph, label_sizes, (NODE_RADIUS + 2) / height_px, edge_widths);
    } else {
      layout.compute(graph, width / height);
    }
    have_layout = true;
  }

  // The map's size (several endpoints), in pixels at 100%.
  float map_width = 0.0f;
  float map_height = 0.0f;
  for (size_t i = 0; i < nodes.size(); i++) {
    std::map<std::string, ImVec2>::const_iterator found = layout.positions.find(nodes[i].key);
    if (found != layout.positions.end()) {
      map_width = std::max(map_width, found->second.x * height_px + labels[i].size.x + 20.0f);
      map_height = std::max(map_height, found->second.y * height_px + labels[i].size.y + 20.0f);
    }
  }
  // Room at the top for the title and the checkboxes' corner.
  float top_room = 2 * base_line + 40.0f;
  float view_width = width;
  float view_height = height - top_room;
  float fit_zoom = std::min(view_width / (map_width > 1 ? map_width : 1),
                            view_height / (map_height > 1 ? map_height : 1));
  if (!several) {
    zoom = 1.0f;
    pan = ImVec2(0, 0);
  } else if (redo && !view_touched) {
    // A fresh layout: as big as fits, but no bigger than full size, and no
    // smaller than readable - beyond that, drag it around.
    zoom = std::min(1.0f, std::max(fit_zoom, 0.7f));
    center_view(map_width, map_height, view_width, view_height, top_room);
  }
  if (fit_pressed) {
    zoom = std::min(fit_zoom, 1.0f);
    center_view(map_width, map_height, view_width, view_height, top_room);
    view_touched = false;
  }
  if (full_pressed) {
    zoom = 1.0f;
    center_view(map_width, map_height, view_width, view_height, top_room);
    view_touched = false;
  }
  float z = zoom;
  float line = base_line * z;
  float radius = NODE_RADIUS * z;

  // Screen position of every node the layout places.
  std::vector<ImVec2> at(nodes.size());
  std::vector<bool> placed(nodes.size(), false);
  for (size_t i = 0; i < nodes.size(); i++) {
    std::map<std::string, ImVec2>::const_iterator found = layout.positions.find(nodes[i].key);
    if (found != layout.positions.end()) {
      at[i] = ImVec2(floorf(area_min.x + (found->second.x * height_px - pan.x) * z) + 0.5f,
                     floorf(area_min.y + (found->second.y * height_px - pan.y) * z) + 0.5f);
      placed[i] = true;
    }
  }

  // Place the labels: below and to the right of the node, where the layout
  // made room. With several endpoints, a label whose spot is crossed by
  // links (often the node's own) or that lands on another label tries the
  // node's other three corners, and takes whichever is clearest.
  if (several) {
    std::vector<ImVec2> placed_min;
    std::vector<ImVec2> placed_max;
    for (size_t i = 0; i < nodes.size(); i++) {
      NodeLabel& label = labels[i];
      if (!placed[i] || !label.shown) {
        continue;
      }
      ImVec2 p = at[i];
      float w = label.size.x * z;
      float h = label.size.y * z;
      float gap_x = radius + 3 * z;
      if (nodes[i].kind == NODE_SILENT || nodes[i].kind == NODE_HERE) {
        label.at = ImVec2(p.x + gap_x + z, nodes[i].kind == NODE_HERE ? p.y - h / 2 : p.y - line / 2);
        placed_min.push_back(label.at);
        placed_max.push_back(ImVec2(label.at.x + w, label.at.y + h));
        continue;
      }
      // Corners, in order of preference: below-right, above-right,
      // below-left, above-left. (`flip` draws right-aligned at at.x.)
      ImVec2 corner_at[4] = {ImVec2(p.x + gap_x, p.y + 2 * z), ImVec2(p.x + gap_x, p.y - 2 * z - h),
                             ImVec2(p.x - gap_x, p.y + 2 * z), ImVec2(p.x - gap_x, p.y - 2 * z - h)};
      bool corner_flip[4] = {false, false, true, true};
      int best = 0;
      float best_cost = 1e30f;
      for (int c = 0; c < 4; c++) {
        float left = corner_flip[c] ? corner_at[c].x - w : corner_at[c].x;
        float top = corner_at[c].y;
        float right = left + w;
        float bottom = top + h;
        // Links through the box, weighted by how wide they're drawn...
        float cost = 0.0f;
        for (size_t e = 0; e < edges.size(); e++) {
          if (!placed[edges[e].from] || !placed[edges[e].to]) {
            continue;
          }
          ImVec2 a = at[edges[e].from];
          ImVec2 b = at[edges[e].to];
          float grow = edge_pixels[e] * z / 2;
          // Sample along the link: cheap, and plenty for a few dozen links.
          for (int k = 1; k < 16; k++) {
            float t = k / 16.0f;
            float x = a.x + (b.x - a.x) * t;
            float y = a.y + (b.y - a.y) * t;
            if (x > left - grow && x < right + grow && y > top - grow && y < bottom + grow) {
              cost += 1.0f + grow;
            }
          }
        }
        // ...other labels and nodes in the way...
        for (size_t k = 0; k < placed_min.size(); k++) {
          float overlap_x = std::min(right, placed_max[k].x) - std::max(left, placed_min[k].x);
          float overlap_y = std::min(bottom, placed_max[k].y) - std::max(top, placed_min[k].y);
          if (overlap_x > 0 && overlap_y > 0) {
            cost += overlap_x * overlap_y;
          }
        }
        for (size_t j = 0; j < nodes.size(); j++) {
          if (j != i && placed[j] && at[j].x > left - radius && at[j].x < right + radius &&
              at[j].y > top - radius && at[j].y < bottom + radius) {
            cost += 50.0f;
          }
        }
        // ...and a little against moving from the preferred corner.
        cost += c * 0.5f;
        if (cost < best_cost) {
          best_cost = cost;
          best = c;
        }
      }
      label.at = corner_at[best];
      label.flip = corner_flip[best];
      float left = label.flip ? label.at.x - w : label.at.x;
      placed_min.push_back(ImVec2(left, label.at.y));
      placed_max.push_back(ImVec2(left + w, label.at.y + h));
    }
  }
  for (size_t i = 0; i < nodes.size() && !several; i++) {
    NodeLabel& label = labels[i];
    if (!placed[i] || !label.shown) {
      continue;
    }
    const RouteNode& node = nodes[i];
    ImVec2 p = at[i];
    if (node.kind == NODE_SILENT) {
      label.at = ImVec2(p.x + radius + 4 * z, p.y - line / 2);
    } else if (node.kind == NODE_HERE) {
      label.at = ImVec2(p.x + radius + 4 * z, p.y - label.size.y * z / 2);
    } else {
      label.at = ImVec2(p.x + radius + 3 * z, p.y + 2 * z);
      {
        if (label.at.x + label.size.x > area_max.x - 4) {
          label.flip = true;
          label.at.x = p.x - radius - 3;
          label.at.y = p.y - 2 - label.size.y;
          if (label.at.y < area_min.y + 2) {
            label.at.y = p.y + 2;
          }
        } else if (label.at.y + label.size.y > area_max.y - 2) {
          label.at.y = p.y - 2 - label.size.y;
        }
      }
    }
  }

  // What the mouse is over: a node (its dot or its label) first, then a
  // link. With several endpoints, dragging empty space moves the map and
  // the wheel zooms it.
  ImGuiIO& io = ImGui::GetIO();
  ImVec2 mouse = io.MousePos;
  bool mouse_inside = mouse_is_ours && mouse.x >= area_min.x && mouse.x < area_max.x &&
                      mouse.y >= area_min.y && mouse.y < area_max.y;
  int hovered_node = -1;
  int hovered_edge = -1;
  if (mouse_inside && !panning) {
    for (size_t i = 0; i < nodes.size(); i++) {
      float dx = mouse.x - at[i].x;
      float dy = mouse.y - at[i].y;
      float reach = radius + 4;
      if (placed[i] && dx * dx + dy * dy <= reach * reach) {
        hovered_node = (int)i;
      }
    }
    for (size_t i = 0; i < nodes.size() && hovered_node < 0; i++) {
      if (placed[i] && label_contains(labels[i], mouse, z)) {
        hovered_node = (int)i;
      }
    }
    if (hovered_node < 0) {
      float best = 5.0f;
      for (size_t e = 0; e < edges.size(); e++) {
        if (!placed[edges[e].from] || !placed[edges[e].to]) {
          continue;
        }
        float distance = distance_to_segment(mouse, at[edges[e].from], at[edges[e].to]) -
                         edge_pixels[e] * z / 2;
        if (distance < best) {
          best = distance;
          hovered_edge = (int)e;
        }
      }
    }
    if (several && io.MouseWheel != 0.0f) {
      // Zoom around the mouse: the point under it stays under it.
      float new_zoom = zoom * powf(1.15f, io.MouseWheel);
      if (new_zoom < 0.2f) new_zoom = 0.2f;
      if (new_zoom > 3.0f) new_zoom = 3.0f;
      ImVec2 under(pan.x + (mouse.x - area_min.x) / zoom, pan.y + (mouse.y - area_min.y) / zoom);
      zoom = new_zoom;
      pan = ImVec2(under.x - (mouse.x - area_min.x) / zoom, under.y - (mouse.y - area_min.y) / zoom);
      view_touched = true;
    }
    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
      if (hovered_node >= 0 || hovered_edge >= 0) {
        // Select the flows under the mouse, for every endpoint at once; the
        // same click again clears.
        std::vector<FlowMask> clicked(endpoint_count, 0);
        for (int e = 0; e < endpoint_count; e++) {
          if (hovered_node >= 0 && nodes[hovered_node].kind != NODE_HERE) {
            clicked[e] = nodes[hovered_node].uses[e].flows;
          } else if (hovered_edge >= 0) {
            clicked[e] = edges[hovered_edge].flows[e];
          }
        }
        bool same = true;
        for (int e = 0; e < endpoint_count; e++) {
          if (clicked[e] != endpoints[e].selection) {
            same = false;
          }
        }
        for (int e = 0; e < endpoint_count; e++) {
          endpoints[e].selection = same ? 0 : clicked[e];
        }
      } else {
        // Empty space: the start of a drag, or (if the mouse doesn't move)
        // a click that clears the selection.
        panning = true;
        pan_moved = false;
        pan_mouse = mouse;
        pan_start = pan;
      }
    }
  }
  if (panning) {
    if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
      float dx = io.MousePos.x - pan_mouse.x;
      float dy = io.MousePos.y - pan_mouse.y;
      if (fabsf(dx) + fabsf(dy) > 3.0f) {
        pan_moved = true;
      }
      if (pan_moved && several) {
        pan = ImVec2(pan_start.x - dx / zoom, pan_start.y - dy / zoom);
        view_touched = true;
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeAll);
      }
    } else {
      if (!pan_moved) {
        for (int e = 0; e < endpoint_count; e++) {
          endpoints[e].selection = 0;
        }
      }
      panning = false;
    }
  }
  // The positions above were for this frame's pan; if it just changed,
  // they're a frame stale, which nobody will notice.

  // Light up, per endpoint: the selection, plus whatever's hovered here or
  // elsewhere.
  std::vector<FlowMask> lit(endpoint_count, 0);
  bool anything_lit = false;
  for (int e = 0; e < endpoint_count; e++) {
    lit[e] = endpoints[e].selection | endpoints[e].hover_flows;
    if (hovered_edge >= 0) {
      lit[e] |= edges[hovered_edge].flows[e];
    }
    if (hovered_node >= 0 && nodes[hovered_node].kind == NODE_ROUTER) {
      lit[e] |= nodes[hovered_node].uses[e].flows;
    }
    if (lit[e] != 0) {
      anything_lit = true;
    }
    bool hovered = (hovered_edge >= 0 && edges[hovered_edge].flows[e] != 0) ||
                   (hovered_node >= 0 && nodes[hovered_node].kind != NODE_HERE &&
                    nodes[hovered_node].uses[e].flows != 0);
    if (hovered && e < 64) {
      hovered_endpoints |= (uint64_t)1 << e;
    }
  }

  // The map may be bigger than the area: draw only inside it.
  draw_list->PushClipRect(ImVec2(area_min.x + 1, area_min.y + 1),
                          ImVec2(area_max.x - 1, area_max.y - 1), true);

  if (several) {
    // Each link as parallel stripes, one per endpoint using it, as thick as
    // that endpoint's share of the link. With something lit, the stripes
    // carrying lit flows stay bright and the rest dim.
    for (size_t k = 0; k < edges.size(); k++) {
      const RouteEdge& edge = edges[k];
      if (!placed[edge.from] || !placed[edge.to]) {
        continue;
      }
      ImVec2 a = at[edge.from];
      ImVec2 b = at[edge.to];
      float dx = b.x - a.x;
      float dy = b.y - a.y;
      float length = sqrtf(dx * dx + dy * dy);
      if (length < 1.0f) {
        continue;
      }
      float normal_x = -dy / length;
      float normal_y = dx / length;
      float offset = -edge_pixels[k] * z / 2.0f;
      for (int e = 0; e < endpoint_count; e++) {
        if (edge.flows[e] == 0) {
          continue;
        }
        int flow_count = endpoints[e].flow_count > 0 ? endpoints[e].flow_count : 1;
        float thickness = (1.5f + 5.0f * count_flows(edge.flows[e]) / flow_count) * z;
        float middle = offset + thickness / 2.0f;
        offset += thickness + STRIPE_GAP * z;
        bool bright = !anything_lit || (edge.flows[e] & lit[e]) != 0;
        ImU32 color = bright ? endpoints[e].color : scale_color(endpoints[e].color, 0.25f);
        draw_list->AddLine(ImVec2(a.x + normal_x * middle, a.y + normal_y * middle),
                           ImVec2(b.x + normal_x * middle, b.y + normal_y * middle), color,
                           thickness);
      }
    }
  } else {
    // One endpoint: links thick in proportion to the flows using them. With
    // something lit, the lit flows' links are drawn over the rest, and only
    // as thick as the lit flows on them.
    float full_width = 9.0f;
    int flow_count = endpoints[0].flow_count > 0 ? endpoints[0].flow_count : 1;
    for (int pass = 0; pass < 2; pass++) {
      for (size_t k = 0; k < edges.size(); k++) {
        const RouteEdge& edge = edges[k];
        if (!placed[edge.from] || !placed[edge.to]) {
          continue;
        }
        FlowMask on = edge.flows[0] & lit[0];
        if (pass == 1 && on == 0) {
          continue;
        }
        FlowMask counted = pass == 1 ? on : edge.flows[0];
        float thickness = 1.0f + full_width * count_flows(counted) / flow_count;
        ImU32 color = pass == 1 ? COLOR_EDGE_LIT : (anything_lit ? COLOR_EDGE_DIM : COLOR_EDGE);
        draw_list->AddLine(at[edge.from], at[edge.to], color, thickness);
      }
    }
  }

  // Nodes and their labels.
  for (size_t i = 0; i < nodes.size(); i++) {
    if (!placed[i]) {
      continue;
    }
    const RouteNode& node = nodes[i];
    const NodeLabel& label = labels[i];
    bool on_lit_path = false;
    for (int e = 0; e < endpoint_count; e++) {
      if ((node.uses[e].flows & lit[e]) != 0) {
        on_lit_path = true;
      }
    }
    bool dim = anything_lit && !on_lit_path;
    ImVec2 p = at[i];
    if (node.kind == NODE_HERE) {
      draw_list->AddCircleFilled(p, radius + 2 * z, COLOR_HERE);
    } else if (node.kind == NODE_SILENT) {
      // "*" for a hop that's certainly silent, "?" for one that may just
      // have lost a probe or two: big, so they're easy to tell apart.
      const char* glyph = node.uncertain ? "?" : "*";
      float silent_radius = radius + 3 * z;
      draw_list->AddCircleFilled(p, silent_radius, dim ? COLOR_EDGE_DIM : COLOR_SILENT);
      draw_list->AddCircle(p, silent_radius, dim ? COLOR_EDGE_DIM : IM_COL32(150, 150, 150, 255),
                           0, 1.0f);
      ImVec2 size = big_text_size(glyph);
      size.x *= z;
      size.y *= z;
      // An asterisk sits high in its box; nudge it down to look centred.
      float nudge = node.uncertain ? 0.0f : size.y * 0.18f;
      draw_list->AddText(big_font, big_size() * z,
                         ImVec2(floorf(p.x - size.x / 2), floorf(p.y - size.y / 2 + nudge)),
                         dim ? COLOR_TEXT_DIM : COLOR_TEXT, glyph);
    } else {
      ImU32 fill = COLOR_NODE;
      float node_radius = radius;
      if (node.target_of != 0) {
        node_radius = radius + 2 * z;
        fill = COLOR_TARGET;
        if (several) {
          for (int e = endpoint_count - 1; e >= 0; e--) {
            if (is_target_of(node, e)) {
              fill = endpoints[e].color;
            }
          }
        }
      }
      if (dim) {
        fill = scale_color(fill, 0.35f);
      } else if (anything_lit && node.target_of == 0 && !several) {
        fill = COLOR_NODE_LIT;
      }
      draw_list->AddCircleFilled(p, node_radius, fill);
      if (node.refused) {
        draw_list->AddCircle(p, node_radius + 3 * z, COLOR_REFUSED, 0, 2.0f);
      }
    }
    if (label.shown) {
      draw_label(draw_list, label, dim && node.kind != NODE_HERE, z, several);
    }
  }
  draw_list->PopClipRect();
  // The title again, over the map (which can be dragged under it).
  ImVec2 title_size = ImGui::CalcTextSize(title.c_str());
  draw_list->AddRectFilled(ImVec2(area_min.x + 1, area_min.y + 1),
                           ImVec2(area_min.x + 10 + title_size.x, area_min.y + 6 + title_size.y),
                           COLOR_BACKGROUND);
  draw_outlined_text(draw_list, ImVec2(area_min.x + 6, area_min.y + 4), COLOR_TEXT,
                     title.c_str(), false, false);

  if (hovered_node >= 0) {
    std::string text;
    describe_node(nodes[hovered_node], endpoints, names, suffixes, &text);
    ImGui::SetTooltip("%s", text.c_str());
  } else if (hovered_edge >= 0) {
    std::string text;
    describe_edge(edges[hovered_edge], endpoints, &text);
    ImGui::SetTooltip("%s", text.c_str());
  }
}

// ---------------------------------------------------------------------------
// The time strip
// ---------------------------------------------------------------------------

void draw_route_lanes(ImDrawList* draw_list, ImVec2 box_min, ImVec2 box_max, float inset_x,
                      float lane_height, const std::vector<RouteLane>& lanes,
                      const ViewWindow& window, double now, bool crosshair_visible,
                      double crosshair_x) {
  draw_list->AddRectFilled(box_min, box_max, COLOR_BACKGROUND);
  float inset_width = (float)(window.columns * CELL_WIDTH);
  double epoch = (window.end - window.start) / window.columns;

  for (size_t k = 0; k < lanes.size(); k++) {
    const RouteLane& lane = lanes[k];
    float top = box_min.y + 1 + k * lane_height;
    float bottom = top + lane_height - 1;
    const Tabulation& tabulation = *lane.tabulation;
    float brightness = lane.on_map ? 1.0f : 0.4f;
    ImU32 shade = scale_color(lane.color, (lane.lit ? 0.45f : 0.22f) * brightness);
    ImU32 mark = scale_color(lane.color, brightness);
    for (int column = 0; column < window.columns; column++) {
      int total = tabulation.get_column_total(column);
      if (total == 0) {
        continue;
      }
      float x0 = inset_x + column * CELL_WIDTH;
      draw_list->AddRectFilled(ImVec2(x0, top), ImVec2(x0 + CELL_WIDTH, bottom), shade);
      int lost = tabulation.get_column_lost(column);
      if (lost > 0) {
        float x = x0 + CELL_WIDTH / 2 + 0.5f;
        float bar_top = bottom - (float)lost / total * (bottom - top);
        draw_list->AddLine(ImVec2(x, bottom), ImVec2(x, bar_top), COLOR_LOSS, 1.0f);
      }
    }
    // A tick per column where a path changed.
    const std::vector<double>& changes = lane.store->get_change_times();
    std::vector<double>::const_iterator it =
        std::lower_bound(changes.begin(), changes.end(), window.start);
    int last_column = -1;
    for (; it != changes.end() && *it < window.end; ++it) {
      int column = (int)((*it - window.start) / epoch);
      if (column == last_column || column < 0 || column >= window.columns) {
        continue;
      }
      last_column = column;
      float x = inset_x + column * CELL_WIDTH + CELL_WIDTH / 2 + 0.5f;
      draw_list->AddLine(ImVec2(x, top), ImVec2(x, bottom), mark, 2.0f);
    }
    if (lane.lit) {
      draw_list->AddRect(ImVec2(box_min.x + 1, top), ImVec2(box_max.x - 1, bottom), COLOR_TEXT);
    }
  }

  draw_time_grid(draw_list, ImVec2(inset_x, box_min.y), box_max, inset_x, inset_width, window,
                 now);
  if (crosshair_visible) {
    float x = floorf(inset_x + (float)crosshair_x * inset_width) + 0.5f;
    draw_list->AddLine(ImVec2(x, box_min.y), ImVec2(x, box_max.y), COLOR_CROSSHAIR);
  }
  draw_list->AddRect(box_min, box_max, COLOR_BORDER);
}
