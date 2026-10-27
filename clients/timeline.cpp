#include "timeline.h"

#include <math.h>

// Same limits as the JS version: never narrower than a minute; the default
// view is two minutes.
static const double MIN_SPAN = 60.0;
static const double DEFAULT_SPAN = 120.0;
static const double ZOOM_STEP = 1.1;   // per wheel notch

Timeline::Timeline() : span(DEFAULT_SPAN), following(true), fixed_end(0.0) {
}

void Timeline::compute_window(double now, int columns, double* start, double* end) const {
  if (columns < 1) {
    columns = 1;
  }
  double epoch = span / columns;
  double right = following ? now : fixed_end;
  // Quantize the right edge UP to an epoch boundary, so "now" is always
  // inside the last column.
  right = ceil(right / epoch) * epoch;
  *end = right;
  *start = right - epoch * columns;
}

void Timeline::zoom(double anchor_time, double anchor_fraction, double wheel, double now,
                    double earliest) {
  double max_span = now - earliest;
  if (max_span < DEFAULT_SPAN) {
    max_span = DEFAULT_SPAN;
  }

  double new_span = span * pow(ZOOM_STEP, -wheel);
  if (new_span < MIN_SPAN) new_span = MIN_SPAN;
  if (new_span > max_span) new_span = max_span;

  double new_start = anchor_time - anchor_fraction * new_span;
  if (new_start < earliest) {
    new_start = earliest;
  }
  double new_end = new_start + new_span;

  span = new_span;
  if (new_end >= now) {
    following = true;
  } else {
    following = false;
    fixed_end = new_end;
  }
}

void Timeline::drag(double anchor_time, double fraction, double now, double earliest) {
  double new_end = anchor_time + (1.0 - fraction) * span;
  if (new_end - span < earliest) {
    new_end = earliest + span;
  }
  if (new_end >= now) {
    following = true;
  } else {
    following = false;
    fixed_end = new_end;
  }
}

void Timeline::follow() {
  following = true;
}

bool Timeline::is_following() const {
  return following;
}
