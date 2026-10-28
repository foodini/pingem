// row_view.h - draws one target's row: the status line, the RTT graph, and
// the summary column beside it.
//
// The graph itself is an image: one texel per (epoch, RTT bucket) cell,
// colored on the CPU from the Tabulation's counts, uploaded as an OpenGL
// texture, and drawn scaled up to 7x3-pixel blocks with nearest-neighbour
// filtering. Everything on top of it - grid, labels, loss bars, crosshair - is
// drawn with ImGui's draw list.
//
// Why color on the CPU rather than in a shader: a 200x100 grid is 20,000
// texels, recolored only when the data changes - a few times a second at
// most. That costs nothing, and it keeps all of our own GL code down to
// creating and filling one texture per row. When route coloring arrives, it's
// a different coloring function, not new GL plumbing. If profiling ever says
// otherwise, the counts can move to the GPU and the coloring into a shader.

#ifndef PINGEM_ROW_VIEW_H
#define PINGEM_ROW_VIEW_H

#include "tabulation.h"
#include "target_history.h"

#include "../third_party/imgui/imgui.h"

#include <stdint.h>
#include <vector>

// Pixel size of one cell. Same as the JS version.
const int CELL_WIDTH = 7;
const int CELL_HEIGHT = 3;

// Things every row needs to agree on, computed once per frame.
struct FrameContext {
  ViewWindow window;
  bool by_flow;                // summary split per flow, selection highlighting on
  double now;                  // wall clock, seconds
  int largest_cell;            // across ALL rows, so colors are comparable
  bool crosshair_visible;
  double crosshair_x;          // 0..1 across the graph inset
  double crosshair_y;          // 0..1 down the graph inset
};

// Where a row's pieces go on screen this frame.
struct RowLayout {
  ImVec2 status_min;
  ImVec2 graph_min;            // the bordered graph box
  ImVec2 graph_max;
  ImVec2 inset_min;            // the cell grid inside it (columns*7 x rows*3)
  ImVec2 summary_min;
  ImVec2 summary_max;
};

class RowView {
public:
  RowView();
  ~RowView();

  // Per frame, in this order: tabulate() every row, then work out the
  // largest cell across all rows, then update_texture() and draw() each row.
  void tabulate(const TargetHistory& history, const ViewWindow& window, bool by_flow);
  void update_texture(const FrameContext& frame);
  void draw(ImDrawList* draw_list, const TargetHistory& history, const RowLayout& layout,
            const FrameContext& frame) const;

  const Tabulation& get_tabulation() const;

  // "By flow" mode: the summary column is split into one histogram strip per
  // flow. Returns which strip `point` is over, or -1.
  int flow_strip_at(const RowLayout& layout, ImVec2 point, int flow_count) const;
  // Clicking a strip selects that flow; clicking it again clears the
  // selection. The selected flow is drawn at full brightness, the rest dimmed.
  void toggle_flow(int flow);
  // One line about a flow, for the tooltip over its strip.
  void describe_flow(int flow, char* out, size_t out_size) const;

private:
  void draw_graph(ImDrawList* draw_list, const RowLayout& layout,
                  const FrameContext& frame) const;
  void draw_summary(ImDrawList* draw_list, const RowLayout& layout,
                    const FrameContext& frame) const;

  Tabulation tabulation;
  bool tabulation_changed;
  unsigned int texture;        // GLuint
  int texture_columns;
  int texture_rows;
  int colored_with_largest;    // largest_cell used for the current texture
  int colored_with_highlight;  // selected flow the texture was colored for (-1 none)
  int selected_flow;           // -1 = none
  std::vector<uint32_t> pixels;
};

// Text with a black outline, readable over any background. (The JS version
// did the same with strokeText.)
void draw_outlined_text(ImDrawList* draw_list, ImVec2 position, ImU32 color, const char* text,
                        bool align_right, bool align_bottom);

#endif
