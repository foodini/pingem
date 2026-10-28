// main.cpp - pingem, the graphical client.
//
//     pingem [--interval S] [--size N] [--flows K] [--font FILE] host [host...]
//
// Talks to user_icmp over its Unix socket (start that first, as root), and
// draws one row per host: status line, RTT heatmap with loss bars, and an RTT
// histogram with summary statistics.
//
// The program is one loop, run once per frame:
//
//   1. handle window/keyboard/mouse events
//   2. poll the daemon connection and feed events into each TargetHistory
//   3. mark packets lost that have waited longer than the loss timeout
//   4. lay out the rows and work out the shared view window
//   5. handle zoom, and find the crosshair
//   6. tabulate every row, then color and draw them
//   7. render and swap
//
// Controls: mouse wheel over a graph zooms around the mouse. Left-click and
// drag scrubs through time: the epoch you grabbed stays under the mouse.
// End (or F) returns to following "now". The "View" button (or V) switches
// the summary column between "combined" and "by flow"; in "by flow", clicking
// a flow's histogram highlights that flow in the graph. The "Scale" button
// (or L) switches the RTT axis between linear and logarithmic. Q or Escape
// quits.

#include "daemon_link.h"
#include "row_view.h"
#include "tabulation.h"
#include "target_history.h"
#include "timeline.h"

#include "../third_party/imgui/backends/imgui_impl_opengl3.h"
#include "../third_party/imgui/backends/imgui_impl_sdl2.h"
#include "../third_party/imgui/imgui.h"

#include <SDL.h>
#include <SDL_opengl.h>

#include <getopt.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
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

// Feeds one daemon event to the history it belongs to.
static void apply_event(const LinkEvent& event, std::vector<TargetHistory*>& histories) {
  if (event.type == LINK_DISCONNECTED) {
    for (size_t i = 0; i < histories.size(); i++) {
      histories[i]->on_session_end();
    }
    return;
  }
  if (event.type == LINK_CONNECTED) {
    return;
  }
  if (event.id < 0 || event.id >= (int)histories.size()) {
    if (event.type == LINK_ERROR) {
      fprintf(stderr, "pingem: user_icmp: %s\n", event.text.c_str());
    }
    return;
  }
  TargetHistory* history = histories[event.id];
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
    default:
      break;
  }
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

  // Target ids are simply indexes into these vectors.
  std::vector<TargetSpec> specs;
  std::vector<TargetHistory*> histories;
  std::vector<RowView*> rows;
  for (size_t i = 0; i < hosts.size(); i++) {
    TargetSpec spec;
    spec.id = (int)i;
    spec.host = hosts[i];
    spec.interval = interval;
    spec.packet_size = packet_size;
    spec.flows = flows;
    specs.push_back(spec);
    histories.push_back(new TargetHistory(hosts[i]));
    rows.push_back(new RowView());
  }
  DaemonLink link(specs);
  Timeline timeline;

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
    io.Fonts->AddFontFromFileTTF(font_path, FONT_SIZE);
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
        if (key == SDLK_q || key == SDLK_ESCAPE) {
          done = true;
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

    // ---- 2. Daemon. ----
    double now = realtime_seconds();
    events.clear();
    link.poll(monotonic_seconds(), &events);
    for (size_t i = 0; i < events.size(); i++) {
      apply_event(events[i], histories);
    }

    // ---- 3. Losses. ----
    for (size_t i = 0; i < histories.size(); i++) {
      histories[i]->check_losses(now, LOSS_TIMEOUT);
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame();
    ImGui::NewFrame();
    ImDrawList* draw_list = ImGui::GetBackgroundDrawList();

    // ---- 4. Layout. Rows share the height equally; within a row, the graph
    // gets 3/4 of the width and the summary the rest. ----
    const float margin = 4.0f;
    const float gap = 4.0f;
    float display_width = io.DisplaySize.x;
    float display_height = io.DisplaySize.y;
    int row_count = (int)rows.size();
    float row_height = floorf((display_height - margin) / row_count);
    float status_height = ImGui::GetTextLineHeight() + 4.0f;
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

    std::vector<RowLayout> layouts(row_count);
    for (int i = 0; i < row_count; i++) {
      RowLayout& layout = layouts[i];
      float top = margin + i * row_height;
      layout.status_min = ImVec2(margin + 2, top + 1);
      layout.graph_min = ImVec2(margin, top + status_height);
      layout.graph_max = ImVec2(margin + graph_width, top + status_height + graph_height);
      layout.inset_min = ImVec2(layout.graph_min.x + inset_left, layout.graph_min.y + inset_top);
      layout.summary_min = ImVec2(layout.graph_max.x + gap, layout.graph_min.y);
      layout.summary_max = ImVec2(layout.summary_min.x + summary_width, layout.graph_max.y);
    }

    // The window every row shows. The RTT scale is shared too, so rows can
    // be compared at a glance.
    ViewWindow view;
    view.columns = columns;
    view.rows = bucket_rows;
    timeline.compute_window(now, columns, &view.start, &view.end);
    view.max_rtt = 0.0;
    double fastest = 0.0;
    for (size_t i = 0; i < histories.size(); i++) {
      double row_max = max_rtt_in_window(*histories[i], view.start, view.end);
      if (row_max > view.max_rtt) {
        view.max_rtt = row_max;
      }
      double row_min = min_rtt_in_window(*histories[i], view.start, view.end);
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

    // ---- 5. Crosshair and zoom: is the mouse over any row's cell grid? ----
    FrameContext frame;
    frame.window = view;
    frame.by_flow = by_flow;
    frame.now = now;
    frame.crosshair_visible = false;
    frame.crosshair_x = 0.0;
    frame.crosshair_y = 0.0;
    float inset_width = (float)(columns * CELL_WIDTH);
    float inset_height = (float)(bucket_rows * CELL_HEIGHT);
    for (int i = 0; i < row_count; i++) {
      const RowLayout& layout = layouts[i];
      double fx = (io.MousePos.x - layout.inset_min.x) / inset_width;
      double fy = (io.MousePos.y - layout.inset_min.y) / inset_height;
      if (fx >= 0.0 && fx <= 1.0 && fy >= 0.0 && fy <= 1.0) {
        frame.crosshair_visible = true;
        frame.crosshair_x = fx;
        frame.crosshair_y = fy;
      }
    }
    double earliest = now;
    for (size_t i = 0; i < histories.size(); i++) {
      const std::vector<Sample>& samples = histories[i]->get_samples();
      if (!samples.empty() && samples[0].send_time < earliest) {
        earliest = samples[0].send_time;
      }
    }
    if (frame.crosshair_visible && io.MouseWheel != 0.0f && !dragging) {
      double anchor_time = view.start + frame.crosshair_x * (view.end - view.start);
      timeline.zoom(anchor_time, frame.crosshair_x, io.MouseWheel, now, earliest);
    }
    // Clicks on ImGui widgets (the View button) belong to them, not to us.
    bool mouse_is_ours = !io.WantCaptureMouse;
    if (frame.crosshair_visible && mouse_is_ours &&
        ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
      dragging = true;
      drag_anchor_time = view.start + frame.crosshair_x * (view.end - view.start);
    }
    if (dragging) {
      if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        // Uses the mouse's x even when it has wandered outside the graph, so
        // a long drag doesn't stall at the edge.
        double fx = (io.MousePos.x - layouts[0].inset_min.x) / inset_width;
        timeline.drag(drag_anchor_time, fx, now, earliest);
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
      } else {
        dragging = false;
      }
    }

    // In "by flow" mode: hovering over a flow's histogram explains it, and
    // clicking it toggles the highlight.
    if (by_flow && mouse_is_ours && !dragging) {
      for (int i = 0; i < row_count; i++) {
        int flow = rows[i]->flow_strip_at(layouts[i], io.MousePos,
                                          histories[i]->get_flow_count());
        if (flow < 0) {
          continue;
        }
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
          rows[i]->toggle_flow(flow);
        }
        char description[256];
        rows[i]->describe_flow(flow, description, sizeof(description));
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

    // ---- 6. Tabulate all rows, find the fullest cell anywhere, then color
    // and draw. ----
    frame.largest_cell = 1;
    for (int i = 0; i < row_count; i++) {
      rows[i]->tabulate(*histories[i], view, by_flow);
      int largest = rows[i]->get_tabulation().get_largest_cell();
      if (largest > frame.largest_cell) {
        frame.largest_cell = largest;
      }
    }
    for (int i = 0; i < row_count; i++) {
      rows[i]->update_texture(frame);
      rows[i]->draw(draw_list, *histories[i], layouts[i], frame);
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
  for (size_t i = 0; i < rows.size(); i++) {
    delete rows[i];
    delete histories[i];
  }
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplSDL2_Shutdown();
  ImGui::DestroyContext();
  SDL_GL_DeleteContext(gl_context);
  SDL_DestroyWindow(window);
  SDL_Quit();
  return 0;
}
