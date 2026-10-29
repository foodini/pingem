#include "row_view.h"

#include <SDL_opengl.h>

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <time.h>
#include <utility>

// Colors, matching the JS version.
static const ImU32 COLOR_BORDER = IM_COL32(128, 128, 128, 255);
static const ImU32 COLOR_LABEL = IM_COL32(255, 96, 96, 255);
static const ImU32 COLOR_GRID = IM_COL32(255, 96, 96, 80);
// Darker than the pure red that marks the fullest cell, so the two stay
// distinct.
static const ImU32 COLOR_LOSS = IM_COL32(150, 0, 0, 255);
// With flows selected, everything that isn't one of them is drawn at this
// fraction of its normal brightness.
static const double DIM = 0.3;
static const ImU32 COLOR_LOSS_DIM = IM_COL32(45, 0, 0, 255);
static const ImU32 COLOR_SELECTED_STRIP = IM_COL32(45, 45, 45, 255);
static const ImU32 COLOR_CROSSHAIR = IM_COL32(255, 0, 0, 255);
static const ImU32 COLOR_STATS = IM_COL32(255, 255, 96, 255);
static const ImU32 COLOR_STATS_LABEL = IM_COL32(170, 170, 120, 255);
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
void format_ms(double seconds, const char* suffix, char* out, size_t out_size) {
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

// Vertical time grid. The lines sit on round local clock times (every 30
// seconds, every 5 minutes, every hour...), labeled with that time. Since
// they're pinned to times, they belong to the data: when the graph steps
// left by a column, the lines step with it, and their labels never change.
void draw_time_grid(ImDrawList* draw_list, ImVec2 box_min, ImVec2 box_max, float inset_x,
                    float inset_width, const ViewWindow& window, double now) {
  char text[64];
  double span = window.end - window.start;
  int spacing_index = 0;
  while (spacing_index < TIME_GRID_SPACING_COUNT - 1 &&
         span / 6.0 >= TIME_GRID_SPACINGS[spacing_index]) {
    spacing_index++;
  }
  double spacing = TIME_GRID_SPACINGS[spacing_index];
  // Never draw a line in the future: while following, the right edge is
  // rounded up past "now" to finish the current column.
  double right = window.end < now ? window.end : now;
  double offset = local_utc_offset(right);
  double newest_line = floor((right + offset) / spacing) * spacing - offset;
  for (double line_time = newest_line; line_time > window.start; line_time -= spacing) {
    double fraction = (line_time - window.start) / span;
    float x = floorf(inset_x + (float)fraction * inset_width);
    draw_list->AddLine(ImVec2(x + 0.5f, box_min.y), ImVec2(x + 0.5f, box_max.y), COLOR_GRID);
    format_clock_time(line_time, spacing, text, sizeof(text));
    // Labels sit to the left of their line; skip one that would hang off the
    // left edge rather than draw it cut in half.
    if (x - 2 - ImGui::CalcTextSize(text).x >= box_min.x) {
      draw_outlined_text(draw_list, ImVec2(x - 2, box_max.y - 1), COLOR_LABEL, text, true, true);
    }
  }
}

RowView::RowView()
    : tabulation_changed(true),
      texture(0),
      texture_columns(0),
      texture_rows(0),
      colored_with_largest(-1),
      colored_with_highlight(0),
      selection(0) {
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

void RowView::tabulate(const TargetHistory& history, const ViewWindow& window,
                       bool show_selection) {
  FlowMask highlight = 0;
  if (show_selection) {
    int flow_count = history.get_flow_count();
    FlowMask existing = flow_count >= 64 ? ~(FlowMask)0 : flow_bit(flow_count) - 1;
    highlight = selection & existing;
  }
  if (tabulation.build_if_needed(history, window, highlight)) {
    tabulation_changed = true;
  }
}

void RowView::toggle_flow(int flow) {
  selection = (selection == flow_bit(flow)) ? 0 : flow_bit(flow);
}

void RowView::set_selection(FlowMask new_selection) {
  selection = new_selection;
}

FlowMask RowView::get_selection() const {
  return selection;
}

int RowView::flow_strip_at(const RowLayout& layout, ImVec2 point, int flow_count) const {
  if (flow_count <= 0 || point.x < layout.summary_min.x || point.x >= layout.summary_max.x ||
      point.y < layout.summary_min.y || point.y >= layout.summary_max.y) {
    return -1;
  }
  float strip_width = (layout.summary_max.x - layout.summary_min.x - 2) / flow_count;
  int flow = (int)((point.x - layout.summary_min.x - 1) / strip_width);
  if (flow < 0 || flow >= flow_count) {
    return -1;
  }
  return flow;
}

void RowView::describe_flow(int flow, char* out, size_t out_size) const {
  const FlowStats& stats = tabulation.get_stats(flow);
  int total = stats.get_total();
  if (total == 0) {
    snprintf(out, out_size, "flow %d: no data on screen", flow);
    return;
  }
  char average[32];
  char percentile[32];
  format_ms(stats.get_average(), " avg", average, sizeof(average));
  format_ms(stats.get_percentile(0.9), " 90%", percentile, sizeof(percentile));
  snprintf(out, out_size, "flow %d: %.1f%% loss, %d pkts, %s, %s\n%s", flow,
           100.0 * stats.lost / total, total, average, percentile,
           selection == flow_bit(flow) ? "click to clear the highlight"
                                       : "click to highlight this flow");
}

// The heatmap color for a cell holding `count` replies when the fullest cell
// holds `largest` (same formula as the JS version): dim to bright blue-white
// with how full it is; the fullest cell itself red, unless every cell holds a
// single reply, when "fullest" means nothing and everything would be red.
// `brightness` < 1 dims it, and dimmed cells are never red. `floor` is the
// intensity of a cell holding a single reply: 0.30 normally; higher for a
// highlighted flow, so even its sparsest cells stand out from the dimmed rest.
static uint32_t cell_color(int count, int largest, double brightness, double floor) {
  uint8_t red;
  uint8_t green;
  uint8_t blue;
  if (count == largest && largest > 1 && brightness >= 1.0) {
    red = 255;
    green = 0;
    blue = 0;
  } else {
    double intensity = 0.0;
    if (largest > 1) {
      intensity = (double)(count - 1) / (double)(largest - 1);
    }
    if (intensity > 1.0) intensity = 1.0;
    intensity = (intensity * (1.0 - floor) + floor) * brightness;
    blue = (uint8_t)(intensity * 255.0);
    red = (uint8_t)(intensity * intensity * 255.0);
    green = red;
  }
  // RGBA in memory order, packed little-endian into a uint32.
  return (uint32_t)red | ((uint32_t)green << 8) | ((uint32_t)blue << 16) | ((uint32_t)255 << 24);
}

// Turns counts into colors. Normally each cell is colored by its count
// relative to the fullest cell on screen in ANY row, so rows compare. With a
// flow selected, cells holding that flow's replies are colored by the
// selected flow's counts alone (relative to its own fullest cell), and cells
// holding only other flows are dimmed.
void RowView::update_texture(const FrameContext& frame) {
  int columns = frame.window.columns;
  int rows = frame.window.rows;
  FlowMask highlight = tabulation.get_selection();
  if (!tabulation_changed && colored_with_largest == frame.largest_cell &&
      colored_with_highlight == highlight && texture_columns == columns &&
      texture_rows == rows) {
    return;
  }

  pixels.assign((size_t)columns * rows, 0);
  int largest = frame.largest_cell;
  int largest_selected = tabulation.get_largest_selected_cell();
  for (int column = 0; column < columns; column++) {
    for (int row = 0; row < rows; row++) {
      int count = tabulation.get_count(column, row);
      if (count == 0) {
        continue;
      }
      uint32_t color;
      if (highlight == 0) {
        color = cell_color(count, largest, 1.0, 0.30);
      } else {
        int selected = tabulation.get_selected_count(column, row);
        if (selected > 0) {
          color = cell_color(selected, largest_selected, 1.0, 0.70);
        } else {
          color = cell_color(count, largest, DIM, 0.30);
        }
      }
      // Texture row 0 is the top of the image; RTT bucket 0 is the bottom.
      pixels[(size_t)(rows - 1 - row) * columns + column] = color;
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
  colored_with_highlight = highlight;
}

void RowView::draw(ImDrawList* draw_list, const TargetHistory& history, const RowLayout& layout,
                   const FrameContext& frame) const {
  draw_outlined_text(draw_list, layout.status_min, COLOR_TEXT, history.get_status().c_str(),
                     false, false);
  draw_graph(draw_list, layout, frame);
  draw_summary(draw_list, layout, frame);
}

// A round RTT for a grid label: "0.1ms", "2ms", "50ms", "200ms".
static void format_round_ms(double seconds, char* out, size_t out_size) {
  snprintf(out, out_size, "%gms", seconds * 1000.0);
}

// The log-scale grid. Latency lines go on the round values 1, 2 and 5 of
// every power of ten between the bottom (min_rtt) and the top (max_rtt),
// labeled on the left; the top edge is labeled with the true max. Loss isn't
// logarithmic, so it gets its own short ticks on the right edge at 0, 20, ...
// 100%, measured on the same linear scale as the loss bars.
static void draw_log_grid(ImDrawList* draw_list, const RowLayout& layout,
                          const ViewWindow& window) {
  float inset_height = (float)(window.rows * CELL_HEIGHT);
  float inset_bottom = layout.inset_min.y + inset_height;
  char text[64];

  // The true maximum, at the top.
  format_ms(window.max_rtt, "", text, sizeof(text));
  draw_outlined_text(draw_list, ImVec2(layout.graph_min.x + 2, layout.graph_min.y + 1),
                     COLOR_LABEL, text, false, false);
  float top_label_bottom = layout.graph_min.y + 1 + ImGui::GetTextLineHeight();

  static const double STEPS[] = {1.0, 2.0, 5.0};
  for (double decade = window.min_rtt; decade <= window.max_rtt; decade *= 10.0) {
    for (int step = 0; step < 3; step++) {
      double value = decade * STEPS[step];
      if (value > window.max_rtt * 1.0000001) {
        break;
      }
      float y = floorf(inset_bottom - (float)rtt_to_fraction(window, value) * inset_height);
      if (value > window.min_rtt * 1.0000001) {
        draw_list->AddLine(ImVec2(layout.graph_min.x, y + 0.5f),
                           ImVec2(layout.graph_max.x, y + 0.5f), COLOR_GRID);
      }
      // Labels sit just above their line, and are skipped where they would
      // collide with the max label at the top.
      if (y - ImGui::GetTextLineHeight() - 1 >= top_label_bottom) {
        format_round_ms(value, text, sizeof(text));
        draw_outlined_text(draw_list, ImVec2(layout.graph_min.x + 2, y - 1), COLOR_LABEL, text,
                           false, true);
      }
    }
  }

  for (int percent = 0; percent <= 100; percent += 20) {
    float y = floorf(inset_bottom - inset_height * percent / 100.0f) + 0.5f;
    draw_list->AddLine(ImVec2(layout.graph_max.x - 6, y), ImVec2(layout.graph_max.x, y),
                       COLOR_LABEL);
    snprintf(text, sizeof(text), "%d%%", percent);
    float half = ImGui::GetTextLineHeight() / 2;
    float label_y = y - half;
    if (percent == 0) label_y = y - 2 * half;   // keep inside the graph
    if (percent == 100) label_y = y;
    draw_outlined_text(draw_list, ImVec2(layout.graph_max.x - 8, label_y), COLOR_LABEL, text,
                       true, false);
  }
}

void RowView::draw_graph(ImDrawList* draw_list, const RowLayout& layout,
                         const FrameContext& frame) const {
  const ViewWindow& window = frame.window;
  float inset_width = (float)(window.columns * CELL_WIDTH);
  float inset_height = (float)(window.rows * CELL_HEIGHT);
  ImVec2 inset_max(layout.inset_min.x + inset_width, layout.inset_min.y + inset_height);

  draw_list->AddRectFilled(layout.graph_min, layout.graph_max, IM_COL32(0, 0, 0, 255));
  if (texture != 0) {
    draw_list->AddImage((ImTextureID)(intptr_t)texture, layout.inset_min, inset_max);
  }

  // Loss: a bar per column, as tall as that column's loss fraction. With a
  // flow selected, the whole bar is dimmed and the part of it that belongs
  // to the selected flow is drawn normally from the bottom up - so its
  // height is that flow's share of the column's packets that were lost.
  //
  // Pings a router refused (ICMP Destination Unreachable and friends) are
  // loss too, but drawn dotted, at the bottom of the bar: "refused" and
  // "vanished" point at different problems.
  bool highlighting = tabulation.get_selection() != 0;
  for (int column = 0; column < window.columns; column++) {
    int lost = tabulation.get_column_lost(column);
    if (lost == 0) {
      continue;
    }
    double total = tabulation.get_column_total(column);
    float x = layout.inset_min.x + column * CELL_WIDTH + CELL_WIDTH / 2 + 0.5f;
    float top = inset_max.y - (float)(lost / total) * inset_height;
    ImU32 loss_color = highlighting ? COLOR_LOSS_DIM : COLOR_LOSS;
    int unreachable = tabulation.get_column_unreachable(column);
    float dotted_top = inset_max.y - (float)(unreachable / total) * inset_height;
    if (unreachable > 0) {
      // Two pixels on, one off.
      for (float y = inset_max.y; y > dotted_top; y -= 3.0f) {
        float dash_top = y - 2.0f < dotted_top ? dotted_top : y - 2.0f;
        draw_list->AddRectFilled(ImVec2(x - 0.5f, dash_top), ImVec2(x + 0.5f, y), loss_color);
      }
    }
    if (dotted_top > top) {
      draw_list->AddLine(ImVec2(x, dotted_top), ImVec2(x, top), loss_color, 1.0f);
    }
    if (highlighting) {
      int selected_lost = tabulation.get_selected_column_lost(column);
      if (selected_lost > 0) {
        float selected_top = inset_max.y - (float)(selected_lost / total) * inset_height;
        draw_list->AddLine(ImVec2(x, inset_max.y), ImVec2(x, selected_top), COLOR_LOSS, 1.0f);
      }
    }
  }

  char text[96];
  if (window.log_scale) {
    draw_log_grid(draw_list, layout, window);
  } else {
    // Linear: five evenly spaced lines, latency labels on the left and loss
    // labels on the right sharing them. Positioned on the cell grid (the
    // inset), which is where the cells and loss bars are drawn - not on the
    // slightly taller graph box around it.
    for (int division = 0; division < VERTICAL_LABEL_DIVISIONS; division++) {
      double k = (double)division / VERTICAL_LABEL_DIVISIONS;
      float y = floorf(layout.inset_min.y + (float)k * inset_height);
      if (division > 0) {
        draw_list->AddLine(ImVec2(layout.graph_min.x, y + 0.5f),
                           ImVec2(layout.graph_max.x, y + 0.5f), COLOR_GRID);
      }
      format_ms((1.0 - k) * window.max_rtt, "", text, sizeof(text));
      draw_outlined_text(draw_list, ImVec2(layout.graph_min.x + 2, y + 1), COLOR_LABEL, text,
                         false, false);
      snprintf(text, sizeof(text), "%.1f%%", (1.0 - k) * 100.0);
      draw_outlined_text(draw_list, ImVec2(layout.graph_max.x - 2, y + 1), COLOR_LABEL, text,
                         true, false);
    }
  }

  draw_time_grid(draw_list, layout.graph_min, layout.graph_max, layout.inset_min.x, inset_width,
                 window, frame.now);

  // Crosshair, with latency and date/time at the mouse.
  if (frame.crosshair_visible) {
    float x = floorf(layout.inset_min.x + (float)frame.crosshair_x * inset_width) + 0.5f;
    float y = floorf(layout.inset_min.y + (float)frame.crosshair_y * inset_height) + 0.5f;
    draw_list->AddLine(ImVec2(layout.graph_min.x, y), ImVec2(layout.graph_max.x, y),
                       COLOR_CROSSHAIR);
    draw_list->AddLine(ImVec2(x, layout.graph_min.y), ImVec2(x, layout.graph_max.y),
                       COLOR_CROSSHAIR);

    double latency = fraction_to_rtt(window, 1.0 - frame.crosshair_y);
    double when = window.start + frame.crosshair_x * (window.end - window.start);
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

// One histogram: a bar per RTT bucket, lined up with the graph's rows, in a
// strip from x0 to x0 + width. Bars are scaled so `largest` fills the strip.
static void draw_histogram(ImDrawList* draw_list, const FlowStats& stats, int largest, int rows,
                           float x0, float width, float inset_bottom, float min_length,
                           double brightness) {
  if (largest <= 0) {
    return;
  }
  for (int row = 0; row < rows; row++) {
    int count = stats.buckets[row];
    if (count == 0) {
      continue;
    }
    double ratio = (double)count / largest;
    double intensity = (ratio * 0.6 + 0.4) * brightness;
    uint8_t blue = (uint8_t)(intensity * 255.0);
    uint8_t red_green = (uint8_t)(intensity * intensity * 255.0);
    float length = ceilf((float)ratio * width);
    if (length < min_length) {
      length = min_length;
    }
    float y_bottom = inset_bottom - row * CELL_HEIGHT;
    draw_list->AddRectFilled(ImVec2(x0, y_bottom - CELL_HEIGHT), ImVec2(x0 + length, y_bottom),
                             IM_COL32(red_green, red_green, blue, 255));
  }
}

void RowView::draw_summary(ImDrawList* draw_list, const RowLayout& layout,
                           const FrameContext& frame) const {
  const ViewWindow& window = frame.window;
  float width = layout.summary_max.x - layout.summary_min.x;
  float inset_bottom = layout.inset_min.y + window.rows * CELL_HEIGHT;
  int flow_count = tabulation.get_flow_count();
  FlowMask highlight = tabulation.get_selection();

  draw_list->AddRectFilled(layout.summary_min, layout.summary_max, IM_COL32(0, 0, 0, 255));

  if (frame.by_flow && flow_count > 0) {
    // One narrow histogram per flow, side by side, all on the same scale.
    float strip_width = (width - 2) / flow_count;
    int largest = tabulation.get_largest_flow_bucket();
    for (int flow = 0; flow < flow_count; flow++) {
      float x0 = floorf(layout.summary_min.x + 1 + flow * strip_width);
      float x1 = floorf(layout.summary_min.x + 1 + (flow + 1) * strip_width);
      bool selected = (highlight & flow_bit(flow)) != 0;
      if (selected) {
        draw_list->AddRectFilled(ImVec2(x0, layout.summary_min.y + 1),
                                 ImVec2(x1, layout.summary_max.y - 1), COLOR_SELECTED_STRIP);
      }
      double brightness = (highlight == 0 || selected) ? 1.0 : DIM;
      draw_histogram(draw_list, tabulation.get_stats(flow), largest, window.rows, x0 + 1,
                     x1 - x0 - 3, inset_bottom, 2.0f, brightness);
      if (flow > 0) {
        draw_list->AddLine(ImVec2(x0 + 0.5f, layout.summary_min.y),
                           ImVec2(x0 + 0.5f, layout.summary_max.y), COLOR_GRID);
      }
      char label[16];
      snprintf(label, sizeof(label), "%d", flow);
      float label_width = ImGui::CalcTextSize(label).x;
      draw_outlined_text(draw_list,
                         ImVec2((x0 + x1) / 2 - label_width / 2, layout.summary_max.y - 1),
                         selected ? COLOR_TEXT : COLOR_LABEL, label, false, true);
    }
  } else {
    // One histogram of every reply in the window.
    const FlowStats& stats = tabulation.get_stats(-1);
    draw_histogram(draw_list, stats, stats.largest_bucket, window.rows, layout.summary_min.x + 1,
                   width - 2, inset_bottom, 5.0f, 1.0);
  }

  // Statistics, top right: for the selected flow if there is one, otherwise
  // for everything. Each is a small label with its value on the line below,
  // so the column can be narrow; the ones that don't fit the height are left
  // off, least important last.
  const FlowStats& stats =
      highlight != 0 ? tabulation.get_selection_stats() : tabulation.get_stats(-1);
  if (stats.get_total() > 0) {
    std::vector<std::pair<std::string, std::string> > items;
    char text[64];
    if (highlight != 0) {
      std::string flows = describe_flow_mask(highlight);
      bool single = (highlight & (highlight - 1)) == 0;
      items.push_back(std::make_pair(std::string(single ? "flow" : "flows"), flows));
    }
    snprintf(text, sizeof(text), "%.1f%%", 100.0 * stats.lost / stats.get_total());
    items.push_back(std::make_pair(std::string("loss"), std::string(text)));
    if (stats.unreachable > 0) {
      snprintf(text, sizeof(text), "%.1f%%", 100.0 * stats.unreachable / stats.get_total());
      items.push_back(std::make_pair(std::string("of it refused"), std::string(text)));
    }
    if (!stats.sorted_rtts.empty()) {
      format_ms(stats.get_average(), "", text, sizeof(text));
      items.push_back(std::make_pair(std::string("avg"), std::string(text)));
      format_ms(stats.get_percentile(0.9), "", text, sizeof(text));
      items.push_back(std::make_pair(std::string("90%"), std::string(text)));
    }
    snprintf(text, sizeof(text), "%d", stats.get_total());
    items.push_back(std::make_pair(std::string("pkts"), std::string(text)));

    float x = layout.summary_max.x - 2;
    float y = layout.summary_min.y + 1;
    float line = ImGui::GetTextLineHeight();
    for (size_t i = 0; i < items.size(); i++) {
      if (y + 2 * line > layout.summary_max.y - 1) {
        break;
      }
      draw_outlined_text(draw_list, ImVec2(x, y), COLOR_STATS_LABEL, items[i].first.c_str(), true,
                         false);
      draw_outlined_text(draw_list, ImVec2(x, y + line),
                         (highlight != 0 && i == 0) ? COLOR_TEXT : COLOR_STATS,
                         items[i].second.c_str(), true, false);
      y += 2 * line;
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
