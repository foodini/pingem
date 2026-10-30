// main.cpp - pingem, the graphical client.
//
//     pingem [--interval S] [--size N] [--flows K] [--font FILE] host [host...]
//
// Talks to user_icmp over its Unix socket (start that first, as root), and
// draws one row per host: status line, RTT heatmap with loss bars, and an RTT
// histogram with summary statistics. Each row's route button opens a graph of
// the paths to that host (route_view.h).
//
// The program is one loop, run once per frame:
//
//   1. handle window/keyboard/mouse events
//   2. poll the daemon connection and feed events into each target
//   3. mark packets lost that have waited longer than the loss timeout
//   4. lay out the rows (and the route graph, if open) and work out the
//      shared view window
//   5. handle zoom, and find the crosshair
//   6. tabulate every row, then color and draw them, and the route graph
//   7. render and swap
//
// Controls: mouse wheel over a graph zooms around the mouse. Left-click and
// drag scrubs through time: the epoch you grabbed stays under the mouse.
// End (or F) returns to following "now". The "View" button (or V) switches
// the summary column between "combined" and "by flow"; in "by flow", clicking
// a flow's histogram highlights that flow in the graph. The "Scale" button
// (or L) switches the RTT axis between linear and logarithmic. Left of each
// status line: X stops pinging that host, and the route button opens (or
// closes) its route graph. R opens the route map with every host on it.
// Escape closes the route view, or quits if none is open; Q quits.

#include "daemon_link.h"
#include "public_suffix.h"
#include "reverse_dns.h"
#include "route_store.h"
#include "route_view.h"
#include "row_view.h"
#include "tabulation.h"
#include "target_history.h"
#include "timeline.h"

#include "../third_party/imgui/backends/imgui_impl_opengl3.h"
#include "../third_party/imgui/backends/imgui_impl_sdl2.h"
#include "../third_party/imgui/imgui.h"

#include <SDL.h>
#include <SDL_opengl.h>

#include <algorithm>
#include <getopt.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <time.h>
#include <vector>

// A packet is declared lost if no reply comes within this many seconds.
// Same as the JS version.
static const double LOSS_TIMEOUT = 3.0;

static const char* DEFAULT_FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf";
static const float FONT_SIZE = 15.0f;

static double monotonic_seconds() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static double realtime_seconds() {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void usage(const char* program) {
  fprintf(stderr,
          "usage: %s [options] host [host...]\n"
          "  --interval S   seconds between pings to each host (default 1)\n"
          "  --size N       ICMP packet size in bytes (default 64)\n"
          "  --flows K      spread each host's pings over K fixed-checksum flows\n"
          "                 (default 8; 0 = let the checksum vary, like plain ping)\n"
          "  --font FILE    TTF font (default %s)\n"
          "With no hosts: 8.8.8.8 amazon.com speedtest.net\n",
          program, DEFAULT_FONT);
}

static bool file_exists(const char* path) {
  FILE* file = fopen(path, "rb");
  if (file == NULL) {
    return false;
  }
  fclose(file);
  return true;
}

// Route probes per ping interval: a trickle normally, enough to notice a
// route change; more while the route view is open, so the graph fills in
// quickly.
static const double PROBE_RATE_BACKGROUND = 1.0;
static const double PROBE_RATE_ROUTE_VIEW = 4.0;

// Everything about one host. `id` is what the daemon knows it by; it never
// changes and is never reused, even after the target is closed.
struct Target {
  int id;
  TargetHistory* history;
  RouteStore* routes;
  RowView* row;
};

static Target* find_target(std::vector<Target>& targets, int id) {
  for (size_t i = 0; i < targets.size(); i++) {
    if (targets[i].id == id) {
      return &targets[i];
    }
  }
  return NULL;
}

// Feeds one daemon event to the target it belongs to.
static void apply_event(const LinkEvent& event, std::vector<Target>& targets) {
  if (event.type == LINK_DISCONNECTED) {
    for (size_t i = 0; i < targets.size(); i++) {
      targets[i].history->on_session_end();
    }
    return;
  }
  if (event.type == LINK_CONNECTED) {
    return;
  }
  Target* target = find_target(targets, event.id);
  if (target == NULL) {
    if (event.type == LINK_ERROR) {
      fprintf(stderr, "pingem: user_icmp: %s\n", event.text.c_str());
    }
    return;   // or about a target that's been closed
  }
  TargetHistory* history = target->history;
  switch (event.type) {
    case LINK_ADDED:
      history->on_added(event.address);
      break;
    case LINK_ERROR:
      history->on_error(event.text);
      break;
    case LINK_PING:
      history->on_ping(event.seq, event.time, event.flow);
      break;
    case LINK_REPLY:
      history->on_reply(event.seq, event.time, event.rtt, event.ttl, event.address);
      break;
    case LINK_UNREACHABLE:
      history->on_unreachable(event.seq, event.time, event.address, event.error_type,
                              event.error_code);
      break;
    case LINK_HOP:
      target->routes->on_hop(event.flow, event.ttl, event.time, event.rtt, event.address,
                             event.reached, event.error_code);
      break;
    default:
      break;
  }
}

enum RowButton {
  ROW_BUTTON_NONE,
  ROW_BUTTON_CLOSE,
  ROW_BUTTON_ROUTES
};

// The two small buttons at the start of a row's status line: X (stop pinging
// this host) and the route button, whose icon is a little path - dots joined
// by lines, forking. `routes_open` draws the route button pressed in.
static RowButton draw_row_buttons(int id, ImVec2 position, float size, const std::string& host,
                                  bool routes_open, bool can_route) {
  RowButton pressed = ROW_BUTTON_NONE;
  char window_name[32];
  snprintf(window_name, sizeof(window_name), "row_buttons_%d", id);
  ImGui::SetNextWindowPos(position);
  ImGui::SetNextWindowBgAlpha(0.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 0));
  ImGui::Begin(window_name, NULL,
               ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                   ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                   ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove);
  ImDrawList* draw_list = ImGui::GetWindowDrawList();
  ImU32 idle = ImGui::GetColorU32(ImGuiCol_Button);
  ImU32 hot = ImGui::GetColorU32(ImGuiCol_ButtonHovered);
  ImU32 active = ImGui::GetColorU32(ImGuiCol_ButtonActive);
  ImU32 ink = IM_COL32(230, 230, 230, 255);
  float inset = floorf(size * 0.28f);

  // X
  if (ImGui::InvisibleButton("close", ImVec2(size, size))) {
    pressed = ROW_BUTTON_CLOSE;
  }
  ImVec2 a = ImGui::GetItemRectMin();
  ImVec2 b = ImGui::GetItemRectMax();
  draw_list->AddRectFilled(a, b, ImGui::IsItemHovered() ? hot : idle, 3.0f);
  draw_list->AddLine(ImVec2(a.x + inset, a.y + inset), ImVec2(b.x - inset, b.y - inset), ink, 1.5f);
  draw_list->AddLine(ImVec2(b.x - inset, a.y + inset), ImVec2(a.x + inset, b.y - inset), ink, 1.5f);
  if (ImGui::IsItemHovered()) {
    ImGui::SetTooltip("Stop pinging %s and remove this row", host.c_str());
  }

  // Route icon: one dot bottom-left, forking to two in the middle, joining
  // at one top-right.
  ImGui::SameLine();
  if (ImGui::InvisibleButton("routes", ImVec2(size, size)) && can_route) {
    pressed = ROW_BUTTON_ROUTES;
  }
  a = ImGui::GetItemRectMin();
  b = ImGui::GetItemRectMax();
  ImU32 fill = routes_open ? active : (ImGui::IsItemHovered() ? hot : idle);
  draw_list->AddRectFilled(a, b, fill, 3.0f);
  ImU32 icon = can_route ? ink : IM_COL32(110, 110, 110, 255);
  ImVec2 start(a.x + inset, b.y - inset);
  ImVec2 upper(a.x + size * 0.38f, a.y + size * 0.40f);
  ImVec2 lower(a.x + size * 0.62f, a.y + size * 0.62f);
  ImVec2 end(b.x - inset, a.y + inset);
  draw_list->AddLine(start, upper, icon, 1.0f);
  draw_list->AddLine(start, lower, icon, 1.0f);
  draw_list->AddLine(upper, end, icon, 1.0f);
  draw_list->AddLine(lower, end, icon, 1.0f);
  float dot = size * 0.09f + 0.5f;
  draw_list->AddCircleFilled(start, dot, icon);
  draw_list->AddCircleFilled(upper, dot, icon);
  draw_list->AddCircleFilled(lower, dot, icon);
  draw_list->AddCircleFilled(end, dot, icon);
  if (ImGui::IsItemHovered()) {
    if (!can_route) {
      ImGui::SetTooltip("Routes need flows (--flows 1 or more)");
    } else if (routes_open) {
      ImGui::SetTooltip("Close the route graph (Escape)");
    } else {
      ImGui::SetTooltip("Show the routes to %s", host.c_str());
    }
  }

  ImGui::End();
  ImGui::PopStyleVar(2);
  return pressed;
}

int main(int argc, char* argv[]) {
  double interval = 1.0;
  int packet_size = 64;
  int flows = 8;
  const char* font_path = DEFAULT_FONT;

  static struct option long_options[] = {
      {"interval", required_argument, NULL, 'i'},
      {"size", required_argument, NULL, 's'},
      {"font", required_argument, NULL, 'f'},
      {"flows", required_argument, NULL, 'k'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0}};
  while (true) {
    int option = getopt_long(argc, argv, "", long_options, NULL);
    if (option == -1) {
      break;
    }
    switch (option) {
      case 'i':
        interval = atof(optarg);
        break;
      case 's':
        packet_size = atoi(optarg);
        break;
      case 'k':
        flows = atoi(optarg);
        break;
      case 'f':
        font_path = optarg;
        break;
      default:
        usage(argv[0]);
        return option == 'h' ? 0 : 2;
    }
  }
  if (!(interval > 0.0)) {
    usage(argv[0]);
    return 2;
  }

  std::vector<std::string> hosts;
  for (int i = optind; i < argc; i++) {
    hosts.push_back(argv[i]);
  }
  if (hosts.empty()) {
    hosts.push_back("8.8.8.8");
    hosts.push_back("amazon.com");
    hosts.push_back("speedtest.net");
  }

  std::vector<Target> targets;
  std::vector<TargetSpec> specs;
  for (size_t i = 0; i < hosts.size(); i++) {
    TargetSpec spec;
    spec.id = (int)i;
    spec.host = hosts[i];
    spec.interval = interval;
    spec.packet_size = packet_size;
    spec.flows = flows;
    spec.probe_rate = flows > 0 ? PROBE_RATE_BACKGROUND : 0.0;
    specs.push_back(spec);
    Target target;
    target.id = (int)i;
    target.history = new TargetHistory(hosts[i]);
    target.routes = new RouteStore();
    target.row = new RowView();
    targets.push_back(target);
  }
  DaemonLink link(specs);
  Timeline timeline;
  ReverseDns names;

  // For naming who owns each router. See public_suffix.h.
  PublicSuffixList suffixes;
  std::string suffix_path = PublicSuffixList::default_path();
  if (suffixes.load(suffix_path)) {
    struct stat info;
    double six_months = 182.0 * 24 * 3600;
    if (stat(suffix_path.c_str(), &info) == 0 &&
        realtime_seconds() - (double)info.st_mtime > six_months) {
      fprintf(stderr,
              "pingem: note: %s is over six months old;\n"
              "  \"make update-psl\" in the clients directory fetches a fresh one.\n",
              suffix_path.c_str());
    }
  }

  // ---- Window, GL context, ImGui. ----
  if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
    fprintf(stderr, "pingem: SDL_Init: %s\n", SDL_GetError());
    return 1;
  }
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
  SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
  SDL_Window* window = SDL_CreateWindow(
      "pingem", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1400, 900,
      (SDL_WindowFlags)(SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI));
  if (window == NULL) {
    fprintf(stderr, "pingem: SDL_CreateWindow: %s\n", SDL_GetError());
    return 1;
  }
  SDL_GLContext gl_context = SDL_GL_CreateContext(window);
  if (gl_context == NULL) {
    fprintf(stderr, "pingem: SDL_GL_CreateContext: %s\n", SDL_GetError());
    return 1;
  }
  SDL_GL_MakeCurrent(window, gl_context);
  SDL_GL_SetSwapInterval(1);   // vsync, if the driver offers it

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  io.IniFilename = NULL;       // no imgui.ini droppings
  ImGui::StyleColorsDark();
  if (file_exists(font_path)) {
    io.Fonts->AddFontFromFileTTF(font_path, FONT_SIZE);   // the first is the default
    // A larger size of the same face, for the route graph's "here", target
    // names, and "*" / "?". The "x" in "*x5" needs the multiplication sign.
    static const ImWchar ranges[] = {0x0020, 0x00FF, 0};
    set_route_view_big_font(io.Fonts->AddFontFromFileTTF(font_path, FONT_SIZE * 1.35f, NULL, ranges));
  } else {
    fprintf(stderr, "pingem: font %s not found; using ImGui's built-in font\n", font_path);
  }
  ImGui_ImplSDL2_InitForOpenGL(window, gl_context);
  // Normally we get desktop GL 3.0. Some setups (EGL-only X servers, some
  // Wayland sessions) hand back OpenGL ES 3 instead, whose shaders need a
  // different version line. Everything else we do works on both.
  const char* gl_version = (const char*)glGetString(GL_VERSION);
  bool is_gles = gl_version != NULL && strncmp(gl_version, "OpenGL ES", 9) == 0;
  ImGui_ImplOpenGL3_Init(is_gles ? "#version 300 es" : "#version 130");

  std::vector<LinkEvent> events;
  bool done = false;
  // Scrubbing: while the left button is held after a click on a graph, the
  // time that was under the mouse at the click stays under the mouse.
  bool dragging = false;
  // "combined" (one summary histogram per row) or "by flow" (one per flow).
  bool by_flow = false;
  // Vertical axis: linear from 0, or logarithmic.
  bool log_scale = false;
  double drag_anchor_time = 0.0;
  // The route view: open or not, and which targets it shows (by id, in
  // `targets` order). One checked = that target's row on top and its graph;
  // several = the all-routes map under a time strip.
  bool routes_open = false;
  std::vector<int> route_checked;
  RouteView route_view;
  // Requests from keys and buttons, acted on at the top of the next frame
  // (never while drawing or iterating).
  int close_request = -1;
  int route_request = -1;
  int toggle_request = -1;
  bool all_routes_request = false;

  while (!done) {
    // ---- 1. Events. Sleep up to 50 ms waiting for one: the data only
    // changes a few times a second, so there's no reason to spin the CPU at
    // the display's refresh rate when nobody's touching anything. ----
    SDL_Event event;
    bool have_event = SDL_WaitEventTimeout(&event, 50) != 0;
    while (have_event) {
      ImGui_ImplSDL2_ProcessEvent(&event);
      if (event.type == SDL_QUIT) {
        done = true;
      } else if (event.type == SDL_KEYDOWN) {
        SDL_Keycode key = event.key.keysym.sym;
        if (key == SDLK_q) {
          done = true;
        } else if (key == SDLK_ESCAPE) {
          if (routes_open) {
            routes_open = false;
          } else {
            done = true;
          }
        } else if (key == SDLK_r) {
          all_routes_request = true;
        } else if (key == SDLK_END || key == SDLK_f) {
          timeline.follow();
        } else if (key == SDLK_v) {
          by_flow = !by_flow;
        } else if (key == SDLK_l) {
          log_scale = !log_scale;
        }
      }
      have_event = SDL_PollEvent(&event) != 0;
    }

    // Requests from last frame. R opens the view with every target (or
    // closes it); a row's route button opens it with just that one (or
    // closes it, if that's all it shows); the checkboxes add and remove.
    if (all_routes_request) {
      if (routes_open) {
        routes_open = false;
      } else if (flows > 0 && !targets.empty()) {
        route_checked.clear();
        for (size_t i = 0; i < targets.size(); i++) {
          route_checked.push_back(targets[i].id);
        }
        routes_open = true;
        route_view.reset();
      }
      all_routes_request = false;
    }
    if (route_request >= 0) {
      if (routes_open && route_checked.size() == 1 && route_checked[0] == route_request) {
        routes_open = false;
      } else if (!routes_open) {
        route_checked.assign(1, route_request);
        routes_open = true;
        route_view.reset();
      } else {
        toggle_request = route_request;   // add it
      }
      route_request = -1;
    }
    if (toggle_request >= 0) {
      std::vector<int> now_checked;
      bool was_checked = false;
      for (size_t i = 0; i < targets.size(); i++) {
        int id = targets[i].id;
        bool checked = std::find(route_checked.begin(), route_checked.end(), id) !=
                       route_checked.end();
        if (id == toggle_request) {
          was_checked = checked;
          checked = !checked;
        }
        if (checked) {
          now_checked.push_back(id);
        }
      }
      // The last one can't be unchecked (the checkbox is disabled, but be
      // sure).
      if (!(was_checked && now_checked.empty())) {
        route_checked = now_checked;
      }
      toggle_request = -1;
    }
    if (close_request >= 0) {
      for (size_t i = 0; i < targets.size(); i++) {
        if (targets[i].id == close_request) {
          link.remove_target(close_request);
          delete targets[i].row;
          delete targets[i].routes;
          delete targets[i].history;
          targets.erase(targets.begin() + i);
          break;
        }
      }
      route_checked.erase(std::remove(route_checked.begin(), route_checked.end(), close_request),
                          route_checked.end());
      if (route_checked.empty()) {
        routes_open = false;
      }
      close_request = -1;
    }
    // Probe faster for whatever the route view is showing.
    for (size_t i = 0; i < targets.size(); i++) {
      if (flows == 0) {
        break;
      }
      bool shown_in_routes =
          routes_open && std::find(route_checked.begin(), route_checked.end(), targets[i].id) !=
                             route_checked.end();
      link.set_probe_rate(targets[i].id,
                          shown_in_routes ? PROBE_RATE_ROUTE_VIEW : PROBE_RATE_BACKGROUND);
    }
    bool routes_single = routes_open && route_checked.size() == 1;
    bool routes_several = routes_open && route_checked.size() > 1;

    // ---- 2. Daemon. ----
    double now = realtime_seconds();
    events.clear();
    link.poll(monotonic_seconds(), &events);
    for (size_t i = 0; i < events.size(); i++) {
      apply_event(events[i], targets);
    }
    names.poll();

    // ---- 3. Losses. ----
    for (size_t i = 0; i < targets.size(); i++) {
      targets[i].history->check_losses(now, LOSS_TIMEOUT);
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame();
    ImGui::NewFrame();
    ImDrawList* draw_list = ImGui::GetBackgroundDrawList();

    // ---- 4. Layout. Normally the rows share the height equally. With one
    // target's routes open, only its row is shown, short, at the top, and
    // the graph has the rest. With several, there are no rows: a time strip
    // with a lane per target, then the map. Within a row, the graph gets 3/4
    // of the width and the summary the rest. ----
    const float margin = 4.0f;
    const float gap = 4.0f;
    float display_width = io.DisplaySize.x;
    float display_height = io.DisplaySize.y;
    float line_height = ImGui::GetTextLineHeight();

    // The rows on screen, as indexes into `targets`.
    std::vector<int> shown;
    for (size_t i = 0; i < targets.size(); i++) {
      if (!routes_open || (routes_single && targets[i].id == route_checked[0])) {
        shown.push_back((int)i);
      }
    }
    int row_count = (int)shown.size();
    float row_height;
    if (routes_single) {
      row_height = floorf(display_height * 0.25f);
      if (row_height < 130.0f) row_height = 130.0f;
    } else {
      row_height = floorf((display_height - margin) / (row_count > 0 ? row_count : 1));
    }
    float status_height = line_height + 4.0f;
    float graph_height = row_height - status_height - gap;
    float usable_width = display_width - 2 * margin - gap;
    float graph_width = floorf(usable_width * 0.75f);
    float summary_width = usable_width - graph_width;

    int columns = (int)((graph_width - 2) / CELL_WIDTH);
    int bucket_rows = (int)((graph_height - 2) / CELL_HEIGHT);
    if (columns < 1) columns = 1;
    if (bucket_rows < 1) bucket_rows = 1;
    float inset_left = floorf((graph_width - columns * CELL_WIDTH) / 2);
    float inset_top = floorf((graph_height - bucket_rows * CELL_HEIGHT) / 2);

    // Room for the X and route buttons at the start of each status line.
    float button_size = line_height + 2.0f;
    float buttons_width = 2 * button_size + 8.0f;

    std::vector<RowLayout> layouts(row_count);
    for (int i = 0; i < row_count; i++) {
      RowLayout& layout = layouts[i];
      float top = margin + i * row_height;
      layout.status_min = ImVec2(margin + 2 + buttons_width, top + 1);
      layout.graph_min = ImVec2(margin, top + status_height);
      layout.graph_max = ImVec2(margin + graph_width, top + status_height + graph_height);
      layout.inset_min = ImVec2(layout.graph_min.x + inset_left, layout.graph_min.y + inset_top);
      layout.summary_min = ImVec2(layout.graph_max.x + gap, layout.graph_min.y);
      layout.summary_max = ImVec2(layout.summary_min.x + summary_width, layout.graph_max.y);
    }
    ImVec2 route_min(margin, margin + row_height + gap);
    ImVec2 route_max(display_width - margin, display_height - margin);

    // The all-routes time strip: a heading line, then one lane per target
    // (shown on the map or not, so the lanes - and their checkboxes - don't
    // move as you check and uncheck), then room for the clock labels.
    float lane_height = line_height + 3.0f;
    ImVec2 strip_min(margin, margin + status_height);
    ImVec2 strip_max(display_width - margin,
                     strip_min.y + targets.size() * lane_height + line_height + 4.0f);
    float strip_inset_x = strip_min.x + 1;
    if (routes_several) {
      // The lanes' names (their checkboxes) get a column of their own on
      // the left; time runs across the rest.
      float label_column = 0.0f;
      for (size_t i = 0; i < targets.size(); i++) {
        float width = ImGui::CalcTextSize(targets[i].history->get_name().c_str()).x;
        if (width > label_column) {
          label_column = width;
        }
      }
      label_column += line_height + 14.0f;
      float cells_width = strip_max.x - strip_min.x - label_column - 2;
      columns = (int)(cells_width / CELL_WIDTH);
      if (columns < 1) columns = 1;
      strip_inset_x = floorf(strip_min.x + label_column + (cells_width - columns * CELL_WIDTH));
      route_min = ImVec2(margin, strip_max.y + gap);
    }

    // The window every row shows. The RTT scale is shared too, so rows can
    // be compared at a glance.
    ViewWindow view;
    view.columns = columns;
    view.rows = bucket_rows;
    timeline.compute_window(now, columns, &view.start, &view.end);
    view.max_rtt = 0.0;
    double fastest = 0.0;
    for (int r = 0; r < row_count; r++) {
      const TargetHistory& history = *targets[shown[r]].history;
      double row_max = max_rtt_in_window(history, view.start, view.end);
      if (row_max > view.max_rtt) {
        view.max_rtt = row_max;
      }
      double row_min = min_rtt_in_window(history, view.start, view.end);
      if (row_min > 0.0 && (fastest == 0.0 || row_min < fastest)) {
        fastest = row_min;
      }
    }
    view.log_scale = log_scale;
    if (view.max_rtt <= 0.0) {
      // No replies on screen: show a sane scale - 0..100 ms linear, 1..100 ms
      // log.
      view.max_rtt = 0.1;
      view.min_rtt = 0.001;
    } else {
      // The bottom of the log scale: the largest power of ten strictly below
      // the fastest reply on screen (80 ms -> 10 ms, 8 ms -> 1 ms, 10 ms ->
      // 1 ms). Unused in linear mode.
      view.min_rtt = pow(10.0, ceil(log10(fastest)) - 1.0);
    }
    if (!log_scale) {
      view.min_rtt = 0.0;   // unused; keeps the fastest reply from forcing re-tabulation
    }

    // ---- 5. Crosshair and zoom: is the mouse over any row's cell grid, or
    // the time strip? Those are the places time can be zoomed and dragged. ----
    std::vector<ImVec2> time_area_min;
    std::vector<ImVec2> time_area_size;
    float inset_width = (float)(columns * CELL_WIDTH);
    float inset_height = (float)(bucket_rows * CELL_HEIGHT);
    for (int i = 0; i < row_count; i++) {
      time_area_min.push_back(layouts[i].inset_min);
      time_area_size.push_back(ImVec2(inset_width, inset_height));
    }
    if (routes_several) {
      time_area_min.push_back(ImVec2(strip_inset_x, strip_min.y));
      time_area_size.push_back(ImVec2(inset_width, strip_max.y - strip_min.y));
    }
    FrameContext frame;
    frame.window = view;
    frame.by_flow = by_flow;
    frame.now = now;
    frame.crosshair_visible = false;
    frame.crosshair_x = 0.0;
    frame.crosshair_y = 0.0;
    for (size_t i = 0; i < time_area_min.size(); i++) {
      double fx = (io.MousePos.x - time_area_min[i].x) / time_area_size[i].x;
      double fy = (io.MousePos.y - time_area_min[i].y) / time_area_size[i].y;
      if (fx >= 0.0 && fx <= 1.0 && fy >= 0.0 && fy <= 1.0) {
        frame.crosshair_visible = true;
        frame.crosshair_x = fx;
        frame.crosshair_y = fy;
      }
    }
    double earliest = now;
    for (size_t i = 0; i < targets.size(); i++) {
      const std::vector<Sample>& samples = targets[i].history->get_samples();
      if (!samples.empty() && samples[0].send_time < earliest) {
        earliest = samples[0].send_time;
      }
    }
    if (frame.crosshair_visible && io.MouseWheel != 0.0f && !dragging) {
      double anchor_time = view.start + frame.crosshair_x * (view.end - view.start);
      timeline.zoom(anchor_time, frame.crosshair_x, io.MouseWheel, now, earliest);
    }
    // Clicks on ImGui widgets (the buttons) belong to them, not to us.
    bool mouse_is_ours = !io.WantCaptureMouse;
    if (frame.crosshair_visible && mouse_is_ours &&
        ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
      dragging = true;
      drag_anchor_time = view.start + frame.crosshair_x * (view.end - view.start);
    }
    if (dragging) {
      if (ImGui::IsMouseDown(ImGuiMouseButton_Left) && !time_area_min.empty()) {
        // Uses the mouse's x even when it has wandered outside the graph, so
        // a long drag doesn't stall at the edge.
        double fx = (io.MousePos.x - time_area_min[0].x) / inset_width;
        timeline.drag(drag_anchor_time, fx, now, earliest);
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
      } else {
        dragging = false;
      }
    }

    // In "by flow" mode: hovering over a flow's histogram explains it (and
    // lights up its path in an open route graph), and clicking it toggles
    // the highlight.
    int hovered_flow_target = -1;
    FlowMask hovered_flows = 0;
    if (by_flow && mouse_is_ours && !dragging) {
      for (int i = 0; i < row_count; i++) {
        Target& target = targets[shown[i]];
        int flow = target.row->flow_strip_at(layouts[i], io.MousePos,
                                             target.history->get_flow_count());
        if (flow < 0) {
          continue;
        }
        hovered_flow_target = target.id;
        hovered_flows = flow_bit(flow);
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
          target.row->toggle_flow(flow);
        }
        char description[256];
        target.row->describe_flow(flow, description, sizeof(description));
        ImGui::SetTooltip("%s", description);
      }
    }

    // The View and Scale buttons, top right. Real buttons (not just the V
    // and L keys) so the modes can be discovered; their tooltips name the
    // shortcuts.
    const char* view_label = by_flow ? "View: by flow" : "View: combined";
    const char* scale_label = log_scale ? "Scale: log" : "Scale: linear";
    float view_width = ImGui::CalcTextSize("View: combined").x + 12;
    float scale_width = ImGui::CalcTextSize("Scale: linear").x + 12;
    float button_gap = 6.0f;
    float controls_width = view_width + button_gap + scale_width;
    // Small enough to sit in the first row's status line, clear of the graph.
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6, 1));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(button_gap, 0));
    ImGui::SetNextWindowPos(ImVec2(display_width - margin - controls_width - 12, margin));
    ImGui::SetNextWindowBgAlpha(0.0f);
    ImGui::Begin("controls", NULL,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                     ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                     ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove);
    if (ImGui::Button(scale_label, ImVec2(scale_width, 0))) {
      log_scale = !log_scale;
    }
    if (ImGui::IsItemHovered()) {
      ImGui::SetTooltip("RTT axis: linear from 0, or logarithmic - which keeps\n"
                        "fast and slow rows readable on one shared scale.\n"
                        "Shortcut: L");
    }
    ImGui::SameLine();
    if (ImGui::Button(view_label, ImVec2(view_width, 0))) {
      by_flow = !by_flow;
      frame.by_flow = by_flow;
    }
    if (ImGui::IsItemHovered()) {
      ImGui::SetTooltip("Summary column: one combined histogram, or one per flow.\n"
                        "In \"by flow\", click a flow's histogram to highlight it.\n"
                        "Shortcut: V");
    }
    ImGui::End();
    ImGui::PopStyleVar(3);

    // Each row's buttons, at the start of its status line.
    for (int i = 0; i < row_count; i++) {
      const Target& target = targets[shown[i]];
      bool routes_shown = routes_single && route_checked[0] == target.id;
      RowButton pressed = draw_row_buttons(
          target.id, ImVec2(margin + 2, layouts[i].graph_min.y - status_height + 1), button_size,
          target.history->get_name(), routes_shown, flows > 0);
      if (pressed == ROW_BUTTON_CLOSE) {
        close_request = target.id;
      } else if (pressed == ROW_BUTTON_ROUTES) {
        route_request = target.id;
      }
    }

    // ---- 6. Tabulate all rows, find the fullest cell anywhere, then color
    // and draw. ----
    frame.largest_cell = 1;
    for (int i = 0; i < row_count; i++) {
      Target& target = targets[shown[i]];
      bool show_selection = by_flow || routes_single;
      target.row->tabulate(*target.history, view, show_selection);
      int largest = target.row->get_tabulation().get_largest_cell();
      if (largest > frame.largest_cell) {
        frame.largest_cell = largest;
      }
    }
    for (int i = 0; i < row_count; i++) {
      Target& target = targets[shown[i]];
      target.row->update_texture(frame);
      target.row->draw(draw_list, *target.history, layouts[i], frame);
    }

    if (routes_open) {
      std::vector<RouteViewEndpoint> endpoints;
      std::vector<Target*> endpoint_targets;
      for (size_t i = 0; i < targets.size(); i++) {
        Target& target = targets[i];
        if (std::find(route_checked.begin(), route_checked.end(), target.id) ==
            route_checked.end()) {
          continue;
        }
        RouteViewEndpoint endpoint;
        endpoint.target_id = target.id;
        endpoint.name = target.history->get_name();
        endpoint.address = target.history->get_address();
        endpoint.store = target.routes;
        endpoint.flow_count = target.history->get_flow_count();
        endpoint.color = endpoint_color(target.id);
        endpoint.selection = target.row->get_selection();
        endpoint.hover_flows = target.id == hovered_flow_target ? hovered_flows : 0;
        endpoints.push_back(endpoint);
        endpoint_targets.push_back(&target);
      }
      std::string title = routes_single
                              ? "Routes to " + endpoints[0].name +
                                    ", from probes sent during the time shown above"
                              : "All routes, from probes sent during the time shown above";
      route_view.draw(draw_list, route_min, route_max, &endpoints, view.start, view.end, title,
                      &names, suffixes, mouse_is_ours && !dragging, monotonic_seconds());
      for (size_t e = 0; e < endpoints.size(); e++) {
        endpoint_targets[e]->row->set_selection(endpoints[e].selection);
      }

      if (routes_several) {
        draw_outlined_text(draw_list, ImVec2(margin + 2, margin + 1), IM_COL32(255, 255, 255, 255),
                           "Each lane: shaded where there's data, red for loss, a tick where a "
                           "path changed. Drag or scroll it to move in time.",
                           false, false);
        std::vector<RouteLane> lanes;
        uint64_t lit = route_view.get_hovered_endpoints();
        for (size_t i = 0; i < targets.size(); i++) {
          Target& target = targets[i];
          target.row->tabulate(*target.history, view, false);
          RouteLane lane;
          lane.color = endpoint_color(target.id);
          lane.store = target.routes;
          lane.tabulation = &target.row->get_tabulation();
          lane.lit = false;
          lane.on_map = false;
          for (size_t e = 0; e < endpoints.size(); e++) {
            if (endpoints[e].target_id == target.id) {
              lane.on_map = true;
              lane.lit = e < 64 && (lit & ((uint64_t)1 << e)) != 0;
            }
          }
          lanes.push_back(lane);
        }
        draw_route_lanes(draw_list, strip_min, strip_max, strip_inset_x, lane_height, lanes, view,
                         now, frame.crosshair_visible, frame.crosshair_x);
      }

      // The checkboxes choosing which targets the map shows: in the lanes,
      // as their labels, with all routes showing; under the title with one.
      if (routes_several) {
        ImGui::SetNextWindowPos(ImVec2(strip_min.x + 3, strip_min.y + 1));
        ImGui::SetNextWindowBgAlpha(0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(2, 0));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, lane_height - line_height));
      } else {
        ImGui::SetNextWindowPos(ImVec2(route_min.x + 6, route_min.y + 8 + line_height));
        ImGui::SetNextWindowBgAlpha(0.6f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImGui::GetStyle().FramePadding);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImGui::GetStyle().ItemSpacing);
      }
      ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                          routes_several ? ImVec2(0, 0) : ImGui::GetStyle().WindowPadding);
      ImGui::Begin("route_endpoints", NULL,
                   ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                       ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                       ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove);
      for (size_t i = 0; i < targets.size(); i++) {
        Target& target = targets[i];
        bool checked = std::find(route_checked.begin(), route_checked.end(), target.id) !=
                       route_checked.end();
        bool last = checked && route_checked.size() == 1;
        ImGui::PushID(target.id);
        float size = line_height - 4;
        if (!routes_several) {
          ImVec2 swatch = ImGui::GetCursorScreenPos();
          ImGui::GetWindowDrawList()->AddRectFilled(
              ImVec2(swatch.x, swatch.y + 4), ImVec2(swatch.x + size, swatch.y + 4 + size),
              endpoint_color(target.id));
          ImGui::Dummy(ImVec2(size + 4, line_height));
          ImGui::SameLine();
        }
        if (last) {
          ImGui::BeginDisabled();
        }
        bool value = checked;
        // In the lanes, the label is the lane's name, in its color.
        ImU32 label_color = ImGui::GetColorU32(ImGuiCol_Text);
        if (routes_several) {
          label_color = checked ? endpoint_color(target.id) : IM_COL32(130, 130, 130, 255);
        }
        ImGui::PushStyleColor(ImGuiCol_Text, label_color);
        if (ImGui::Checkbox(target.history->get_name().c_str(), &value)) {
          toggle_request = target.id;
        }
        ImGui::PopStyleColor();
        if (last) {
          ImGui::EndDisabled();
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
          ImGui::SetTooltip(last ? "The map shows at least one host.\n"
                                   "Escape or R closes it."
                                 : (checked ? "Take this host off the map"
                                            : "Add this host to the map"));
        }
        ImGui::PopID();
      }
      ImGui::End();
      ImGui::PopStyleVar(3);
    }
    if (targets.empty()) {
      draw_outlined_text(draw_list, ImVec2(margin + 4, margin + 4), IM_COL32(255, 255, 255, 255),
                         "No hosts left. (Q quits.)", false, false);
    }
    if (!timeline.is_following()) {
      // Just left of the buttons.
      draw_outlined_text(draw_list,
                         ImVec2(display_width - margin - controls_width - 24, margin + 1),
                         IM_COL32(255, 255, 96, 255), "viewing history - End to follow", true,
                         false);
    }

    // ---- 7. Render. ----
    ImGui::Render();
    glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
    glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    SDL_GL_SwapWindow(window);
  }

  // Textures belong to the GL context, so the rows go first.
  for (size_t i = 0; i < targets.size(); i++) {
    delete targets[i].row;
    delete targets[i].routes;
    delete targets[i].history;
  }
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplSDL2_Shutdown();
  ImGui::DestroyContext();
  SDL_GL_DeleteContext(gl_context);
  SDL_DestroyWindow(window);
  SDL_Quit();
  return 0;
}
