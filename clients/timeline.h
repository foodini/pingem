// timeline.h - what span of time the graphs show, shared by every row.
//
// Two modes, as in the JS version:
//   following - the right edge is "now", and the graph advances on its own.
//   fixed     - the user has zoomed into the past; the window stays put.
//
// Smooth advance: the window is quantized to whole epochs (one epoch = one
// 7-pixel column). Its right edge sits on a multiple of the epoch length, so
// while following, the graph shifts left exactly one column at a time as each
// epoch boundary passes, instead of every column's contents shimmering as
// boundaries slide through the data on every frame.

#ifndef PINGEM_TIMELINE_H
#define PINGEM_TIMELINE_H

class Timeline {
public:
  Timeline();

  // The visible window for a graph `columns` epochs wide.
  void compute_window(double now, int columns, double* start, double* end) const;

  // Mouse-wheel zoom, anchored so the time under the mouse stays under the
  // mouse. `wheel` > 0 zooms in. `earliest` is the oldest data we have (or
  // `now` if none), which bounds how far out you can zoom.
  void zoom(double anchor_time, double anchor_fraction, double wheel, double now,
            double earliest);

  // Click-and-drag scrubbing: positions the window so that `anchor_time` (the
  // time that was under the mouse when the button went down) is at `fraction`
  // across the graph, where the mouse is now. The span doesn't change.
  // Dragging the newest data to the right edge or beyond resumes following;
  // you can't drag the oldest data past the left edge.
  void drag(double anchor_time, double fraction, double now, double earliest);

  // Back to following "now", keeping the current span.
  void follow();

  bool is_following() const;

private:
  double span;          // seconds across the whole graph
  bool following;
  double fixed_end;     // right edge when not following
};

#endif
