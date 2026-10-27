#include "row_view.h"

#include <SDL_opengl.h>

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// Colors, matching the JS version.
static const ImU32 COLOR_BORDER = IM_COL32(128, 128, 128, 255);
static const ImU32 COLOR_LABEL = IM_COL32(255, 96, 96, 255);
static const ImU32 COLOR_GRID = IM_COL32(255, 96, 96, 80);
static const ImU32 COLOR_LOSS = IM_COL32(64, 160, 64, 255);
static const ImU32 COLOR_CROSSHAIR = IM_COL32(255, 0, 0, 255);
static const ImU32 COLOR_STATS = IM_COL32(255, 255, 96, 255);
static const ImU32 COLOR_TEXT = IM_COL32(255, 255, 255, 255);

static const int VERTICAL_LABEL_DIVISIONS = 5;

// Candidate spacings for the vertical time grid, in seconds. The first one
// that gives no more than ~6 lines across the graph is used.
static const double TIME_GRID_SPACINGS[] = {
    5, 15, 20, 30, 60, 90, 120, 180, 300, 600, 900, 1200, 1800, 3600, 2 * 3600, 3 * 3600,
    4 * 3600, 6 * 3600, 9 * 3600, 12 * 3600, 24 * 3600, 2 * 24 * 3600, 3 * 24 * 3600,
    6 * 24 * 3600, 12 * 24 * 3600};
static const int TIME_GRID_SPACING_COUNT =
    sizeof(TIME_GRID_SPACINGS) / sizeof(TIME_GRID_SPACINGS[0]);

void draw_outlined_text(ImDrawList* draw_list, ImVec2 position, ImU32 color, const char* text,
                        bool align_right, bool align_bottom) {
  ImVec2 size = ImGui::CalcTextSize(text);
  if (align_right) {
    position.x -= size.x;
  }
  if (align_bottom) {
    position.y -= size.y;
  }
  position.x = floorf(position.x);
  position.y = floorf(position.y);
  const ImU32 outline = IM_COL32(0, 0, 0, 255);
  for (int dy = -1; dy <= 1; dy++) {
    for (int dx = -1; dx <= 1; dx++) {
      if (dx != 0 || dy != 0) {
        draw_list->AddText(ImVec2(position.x + dx, position.y + dy), outline, text);
      }
    }
  }
  draw_list->AddText(position, color, text);
}

// Milliseconds with enough decimals to be useful at any scale: on a LAN the
// whole graph can be under a millisecond, where "%.1f" shows 0.1 everywhere.
static void format_ms(double seconds, const char* suffix, char* out, size_t out_size) {
  double ms = seconds * 1000.0;
  const char* format = "%.1fms%s";
  if (ms < 1.0) {
    format = "%.3fms%s";
  } else if (ms < 10.0) {
    format = "%.2fms%s";
  }
  snprintf(out, out_size, format, ms, suffix);
}

// A grid line's label: the local clock time, with only as much precision as
// the grid spacing needs ("13:21:30", "13:20", "Oct 26").
static void format_clock_time(double t, double spacing, char* out, size_t out_size) {
  time_t seconds = (time_t)floor(t + 0.5);
  struct tm local;
  localtime_r(&seconds, &local);
  const char* format = "%b %d";
  if (spacing < 60.0) {
    format = "%H:%M:%S";
  } else if (spacing < 24 * 3600.0) {
    format = "%H:%M";
  }
  strftime(out, out_size, format, &local);
}

// Seconds east of UTC for the local time zone at time t (e.g. -25200 for
// PDT). Grid lines are placed on round LOCAL times, so hour and day lines
// land on the hour and at midnight where you are, not in Greenwich.
static double local_utc_offset(double t) {
  time_t seconds = (time_t)t;
  struct tm local;
  localtime_r(&seconds, &local);
  return (double)local.tm_gmtoff;
}

RowView::RowView()
    : tabulation_changed(true),
      texture(0),
      texture_columns(0),
      texture_rows(0),
      colored_with_largest(-1) {
}

RowView::~RowView() {
  if (texture != 0) {
    GLuint name = texture;
    glDeleteTextures(1, &name);
  }
}

const Tabulation& RowView::get_tabulation() const {
  return tabulation;
}

void RowView::tabulate(const TargetHistory& history, const ViewWindow& window) {
  if (tabulation.build_if_needed(history, window)) {
    tabulation_changed = true;
  }
}

// Turns counts into colors (same formula as the JS version): occupied cells
// range from dim to bright blue-white with how full they are, relative to the
// fullest cell on screen in ANY row; the fullest cell itself is red (unless
// every cell holds a single reply).
void RowView::update_texture(const FrameContext& frame) {
  int columns = frame.window.columns;
  int rows = frame.window.rows;
  if (!tabulation_changed && colored_with_largest == frame.largest_cell &&
      texture_columns == columns && texture_rows == rows) {
    return;
  }

  pixels.assign((size_t)columns * rows, 0);
  int largest = frame.largest_cell;
  for (int column = 0; column < columns; column++) {
    for (int row = 0; row < rows; row++) {
      int count = tabulation.get_count(column, row);
      if (count == 0) {
        continue;
      }
      uint8_t red;
      uint8_t green;
      uint8_t blue;
      // Red marks the fullest cell(s). When no cell holds more than one
      // reply, "fullest" means nothing - and every cell would turn red.
      if (count == largest && largest > 1) {
        red = 255;
        green = 0;
        blue = 0;
      } else {
        double intensity = 0.0;
        if (largest > 1) {
          intensity = (double)(count - 1) / (double)(largest - 1);
        }
        if (intensity > 1.0) intensity = 1.0;
        intensity = intensity * 0.70 + 0.30;
        blue = (uint8_t)(intensity * 255.0);
        red = (uint8_t)(intensity * intensity * 255.0);
        green = red;
      }
      // Texture row 0 is the top of the image; RTT bucket 0 is the bottom.
      size_t texel = (size_t)(rows - 1 - row) * columns + column;
      // RGBA in memory order, packed little-endian into a uint32.
      pixels[texel] = (uint32_t)red | ((uint32_t)green << 8) | ((uint32_t)blue << 16) |
                      ((uint32_t)255 << 24);
    }
  }

  if (texture == 0) {
    GLuint name = 0;
    glGenTextures(1, &name);
    texture = name;
  }
  glBindTexture(GL_TEXTURE_2D, texture);
  // Nearest-neighbour: each texel becomes a crisp 7x3 block.
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
  if (texture_columns != columns || texture_rows != rows) {
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, columns, rows, 0, GL_RGBA, GL_UNSIGNED_BYTE,
                 &pixels[0]);
    texture_columns = columns;
    texture_rows = rows;
  } else {
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, columns, rows, GL_RGBA, GL_UNSIGNED_BYTE,
                    &pixels[0]);
  }

  tabulation_changed = false;
  colored_with_largest = largest;
}

void RowView::draw(ImDrawList* draw_list, const TargetHistory& history, const RowLayout& layout,
                   const FrameContext& frame) const {
  draw_outlined_text(draw_list, layout.status_min, COLOR_TEXT, history.get_status().c_str(),
                     false, false);
  draw_graph(draw_list, layout, frame);
  draw_summary(draw_list, layout, frame);
}

void RowView::draw_graph(ImDrawList* draw_list, const RowLayout& layout,
                         const FrameContext& frame) const {
  const ViewWindow& window = frame.window;
  float inset_width = (float)(window.columns * CELL_WIDTH);
  float inset_height = (float)(window.rows * CELL_HEIGHT);
  ImVec2 inset_max(layout.inset_min.x + inset_width, layout.inset_min.y + inset_height);
  float height = layout.graph_max.y - layout.graph_min.y;

  draw_list->AddRectFilled(layout.graph_min, layout.graph_max, IM_COL32(0, 0, 0, 255));
  if (texture != 0) {
    draw_list->AddImage((ImTextureID)(intptr_t)texture, layout.inset_min, inset_max);
  }

  // Loss: a green bar per column, as tall as that column's loss fraction.
  for (int column = 0; column < window.columns; column++) {
    int lost = tabulation.get_column_lost(column);
    if (lost == 0) {
      continue;
    }
    double fraction = (double)lost / tabulation.get_column_total(column);
    float x = layout.inset_min.x + column * CELL_WIDTH + CELL_WIDTH / 2 + 0.5f;
    draw_list->AddLine(ImVec2(x, inset_max.y), ImVec2(x, inset_max.y - (float)fraction * inset_height),
                       COLOR_LOSS, 1.0f);
  }

  // Horizontal grid with latency labels on the left and loss labels on the
  // right.
  char text[96];
  for (int division = 0; division < VERTICAL_LABEL_DIVISIONS; division++) {
    double k = (double)division / VERTICAL_LABEL_DIVISIONS;
    float y = floorf(layout.graph_min.y + (float)k * height);
    if (division > 0) {
      draw_list->AddLine(ImVec2(layout.graph_min.x, y + 0.5f), ImVec2(layout.graph_max.x, y + 0.5f),
                         COLOR_GRID);
    }
    format_ms((1.0 - k) * window.max_rtt, "", text, sizeof(text));
    draw_outlined_text(draw_list, ImVec2(layout.graph_min.x + 2, y + 1), COLOR_LABEL, text, false,
                       false);
    snprintf(text, sizeof(text), "%.1f%%", (1.0 - k) * 100.0);
    draw_outlined_text(draw_list, ImVec2(layout.graph_max.x - 2, y + 1), COLOR_LABEL, text, true,
                       false);
  }

  // Vertical time grid. The lines sit on round local clock times (every 30
  // seconds, every 5 minutes, every hour...), labeled with that time. Since
  // they're pinned to times, they belong to the data: when the graph steps
  // left by a column, the lines step with it, and their labels never change.
  double span = window.end - window.start;
  int spacing_index = 0;
  while (spacing_index < TIME_GRID_SPACING_COUNT - 1 &&
         span / 6.0 >= TIME_GRID_SPACINGS[spacing_index]) {
    spacing_index++;
  }
  double spacing = TIME_GRID_SPACINGS[spacing_index];
  // Never draw a line in the future: while following, the right edge is
  // rounded up past "now" to finish the current column.
  double right = window.end < frame.now ? window.end : frame.now;
  double offset = local_utc_offset(right);
  double newest_line = floor((right + offset) / spacing) * spacing - offset;
  for (double line_time = newest_line; line_time > window.start; line_time -= spacing) {
    double fraction = (line_time - window.start) / span;
    float x = floorf(layout.inset_min.x + (float)fraction * inset_width);
    draw_list->AddLine(ImVec2(x + 0.5f, layout.graph_min.y), ImVec2(x + 0.5f, layout.graph_max.y),
                       COLOR_GRID);
    format_clock_time(line_time, spacing, text, sizeof(text));
    draw_outlined_text(draw_list, ImVec2(x - 2, layout.graph_max.y - 1), COLOR_LABEL, text, true,
                       true);
  }

  // Crosshair, with latency and date/time at the mouse.
  if (frame.crosshair_visible) {
    float x = floorf(layout.inset_min.x + (float)frame.crosshair_x * inset_width) + 0.5f;
    float y = floorf(layout.inset_min.y + (float)frame.crosshair_y * inset_height) + 0.5f;
    draw_list->AddLine(ImVec2(layout.graph_min.x, y), ImVec2(layout.graph_max.x, y),
                       COLOR_CROSSHAIR);
    draw_list->AddLine(ImVec2(x, layout.graph_min.y), ImVec2(x, layout.graph_max.y),
                       COLOR_CROSSHAIR);

    double latency = (1.0 - frame.crosshair_y) * window.max_rtt;
    double when = window.start + frame.crosshair_x * span;
    time_t when_seconds = (time_t)when;
    struct tm local;
    localtime_r(&when_seconds, &local);
    char date[64];
    strftime(date, sizeof(date), "%Y.%m.%d %H:%M:%S", &local);
    char latency_text[32];
    format_ms(latency, "", latency_text, sizeof(latency_text));
    snprintf(text, sizeof(text), "%s %s", latency_text, date);

    bool left_half = frame.crosshair_x < 0.5;
    bool near_top = (y - layout.graph_min.y) < 20.0f;
    ImVec2 at(left_half ? x + 3 : x - 3, near_top ? y + 2 : y - 2);
    draw_outlined_text(draw_list, at, COLOR_TEXT, text, !left_half, !near_top);
  }

  draw_list->AddRect(layout.graph_min, layout.graph_max, COLOR_BORDER);
}

void RowView::draw_summary(ImDrawList* draw_list, const RowLayout& layout,
                           const FrameContext& frame) const {
  const ViewWindow& window = frame.window;
  float width = layout.summary_max.x - layout.summary_min.x;
  float inset_bottom = layout.inset_min.y + window.rows * CELL_HEIGHT;

  draw_list->AddRectFilled(layout.summary_min, layout.summary_max, IM_COL32(0, 0, 0, 255));

  // Histogram of every reply in the window, one bar per RTT bucket, lined up
  // with the graph's rows.
  int largest = tabulation.get_largest_summary_bucket();
  for (int row = 0; row < window.rows && largest > 0; row++) {
    int count = tabulation.get_summary_bucket(row);
    if (count == 0) {
      continue;
    }
    double ratio = (double)count / largest;
    double intensity = ratio * 0.6 + 0.4;
    uint8_t blue = (uint8_t)(intensity * 255.0);
    uint8_t red_green = (uint8_t)(intensity * intensity * 255.0);
    float length = ceilf((float)ratio * (width - 2));
    if (length < 5.0f) {
      length = 5.0f;
    }
    float y_bottom = inset_bottom - row * CELL_HEIGHT;
    draw_list->AddRectFilled(ImVec2(layout.summary_min.x + 1, y_bottom - CELL_HEIGHT),
                             ImVec2(layout.summary_min.x + 1 + length, y_bottom),
                             IM_COL32(red_green, red_green, blue, 255));
  }

  // Statistics, top right.
  if (tabulation.get_summary_total() > 0) {
    char text[64];
    float x = layout.summary_max.x - 2;
    float y = layout.summary_min.y + 1;
    float line = ImGui::GetTextLineHeight();
    double loss = (double)tabulation.get_summary_lost() / tabulation.get_summary_total();
    snprintf(text, sizeof(text), "%.1f%% loss", loss * 100.0);
    draw_outlined_text(draw_list, ImVec2(x, y), COLOR_STATS, text, true, false);
    snprintf(text, sizeof(text), "%d pkts", tabulation.get_summary_total());
    draw_outlined_text(draw_list, ImVec2(x, y + line), COLOR_STATS, text, true, false);
    if (tabulation.get_summary_replies() > 0) {
      format_ms(tabulation.get_summary_average(), " avg", text, sizeof(text));
      draw_outlined_text(draw_list, ImVec2(x, y + 2 * line), COLOR_STATS, text, true, false);
      format_ms(tabulation.get_summary_percentile(0.9), " 90%", text, sizeof(text));
      draw_outlined_text(draw_list, ImVec2(x, y + 3 * line), COLOR_STATS, text, true, false);
    }
  }

  if (frame.crosshair_visible) {
    float y = floorf(layout.inset_min.y + (float)frame.crosshair_y * window.rows * CELL_HEIGHT) +
              0.5f;
    draw_list->AddLine(ImVec2(layout.summary_min.x, y), ImVec2(layout.summary_max.x, y),
                       COLOR_CROSSHAIR);
  }

  draw_list->AddRect(layout.summary_min, layout.summary_max, COLOR_BORDER);
}
