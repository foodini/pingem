// main.cpp - pingem, the graphical client.
//
//     pingem [--interval S] [--size N] [--font FILE] host [host...]
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
// End (or F) returns to following "now". Q or Escape quits.

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
      history->on_ping(event.seq, event.time);
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
  const char* font_path = DEFAULT_FONT;

  static struct option long_options[] = {
      {"interval", required_argument, NULL, 'i'},
      {"size", required_argument, NULL, 's'},
      {"font", required_argument, NULL, 'f'},
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
    for (size_t i = 0; i < histories.size(); i++) {
      double row_max = max_rtt_in_window(*histories[i], view.start, view.end);
      if (row_max > view.max_rtt) {
        view.max_rtt = row_max;
      }
    }
    if (view.max_rtt <= 0.0) {
      view.max_rtt = 0.1;   // no replies on screen: show a sane 100 ms scale
    }

    // ---- 5. Crosshair and zoom: is the mouse over any row's cell grid? ----
    FrameContext frame;
    frame.window = view;
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
    if (frame.crosshair_visible && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
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

    // ---- 6. Tabulate all rows, find the fullest cell anywhere, then color
    // and draw. ----
    frame.largest_cell = 1;
    for (int i = 0; i < row_count; i++) {
      rows[i]->tabulate(*histories[i], view);
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
      draw_outlined_text(draw_list, ImVec2(display_width - margin - 2, margin + 1),
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
