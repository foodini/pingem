#include "target_history.h"

#include <stdio.h>
#include <string.h>

TargetHistory::TargetHistory(const std::string& name)
    : name(name), session_base(0), oldest_pending(0), version(0), flow_count(0) {
  status = name + ": waiting for user_icmp...";
}

void TargetHistory::on_added(const std::string& resolved_address) {
  address = resolved_address;
  status = name + " (" + address + "): waiting for the first reply...";
}

void TargetHistory::on_error(const std::string& text) {
  status = name + ": " + text;
}

void TargetHistory::on_ping(uint64_t seq, double send_time, int flow) {
  if (flow >= flow_count) {
    flow_count = flow + 1;
  }
  size_t index = session_base + (size_t)(seq - 1);
  // Pings arrive in order over a stream socket, so index == samples.size()
  // always. If that ever weren't true, fill any gap with ABANDONED rather
  // than misfiling later replies.
  while (samples.size() < index) {
    Sample filler;
    filler.send_time = send_time;
    filler.rtt = 0.0f;
    filler.state = SAMPLE_ABANDONED;
    filler.flow = -1;
    samples.push_back(filler);
  }
  if (samples.size() > index) {
    return;  // duplicate
  }
  Sample sample;
  sample.send_time = send_time;
  sample.rtt = 0.0f;
  sample.state = SAMPLE_PENDING;
  sample.flow = (int8_t)flow;
  samples.push_back(sample);
}

void TargetHistory::on_reply(uint64_t seq, double receive_time, double rtt, int ttl,
                             const std::string& from) {
  size_t index = session_base + (size_t)(seq - 1);
  if (index >= samples.size()) {
    return;
  }
  Sample& sample = samples[index];
  if (sample.state != SAMPLE_PENDING) {
    // Already declared lost (arrived after the timeout). Same rule as the JS
    // version: once lost, always lost, so statistics never change behind the
    // viewer's back.
    return;
  }
  sample.state = SAMPLE_REPLIED;
  sample.rtt = (float)rtt;
  version++;

  char line[512];
  snprintf(line, sizeof(line), "%s: received icmp_seq #%llu from %s at %.2f in %.3fms ttl=%d",
           name.c_str(), (unsigned long long)seq, from.c_str(), receive_time, rtt * 1000.0, ttl);
  if (sample.flow >= 0) {
    char flow_text[32];
    snprintf(flow_text, sizeof(flow_text), " flow=%d", sample.flow);
    strncat(line, flow_text, sizeof(line) - strlen(line) - 1);
  }
  status = line;
}

std::string describe_icmp_error(int type, int code) {
  char text[96];
  if (type == 11) {
    // Pings go out with a full TTL (64), so running out means the packet
    // went round in circles.
    return "TTL ran out (a routing loop?)";
  }
  if (type != 3) {
    snprintf(text, sizeof(text), "ICMP error type %d code %d", type, code);
    return text;
  }
  switch (code) {
    case 0: return "network unreachable";
    case 1: return "host unreachable";
    case 2: return "protocol unreachable";
    case 3: return "port unreachable";
    case 4: return "too big for a link (fragmentation needed) - try a smaller --size";
    case 6: return "destination network unknown";
    case 7: return "destination host unknown";
    case 9:
    case 10:
    case 13: return "administratively prohibited (a firewall)";
    default:
      snprintf(text, sizeof(text), "destination unreachable (code %d)", code);
      return text;
  }
}

void TargetHistory::on_unreachable(uint64_t seq, double receive_time, const std::string& from,
                                   int type, int code) {
  size_t index = session_base + (size_t)(seq - 1);
  if (index >= samples.size()) {
    return;
  }
  Sample& sample = samples[index];
  if (sample.state != SAMPLE_PENDING) {
    return;   // same rule as replies: once resolved, never changed
  }
  sample.state = SAMPLE_UNREACHABLE;
  version++;

  char line[512];
  snprintf(line, sizeof(line), "%s: icmp_seq #%llu refused by %s at %.2f: %s", name.c_str(),
           (unsigned long long)seq, from.c_str(), receive_time,
           describe_icmp_error(type, code).c_str());
  status = line;
}

void TargetHistory::on_session_end() {
  for (size_t i = oldest_pending; i < samples.size(); i++) {
    if (samples[i].state == SAMPLE_PENDING) {
      samples[i].state = SAMPLE_ABANDONED;
    }
  }
  oldest_pending = samples.size();
  session_base = samples.size();
  version++;
  status = name + ": lost contact with user_icmp; reconnecting...";
}

void TargetHistory::check_losses(double now, double timeout) {
  while (oldest_pending < samples.size()) {
    Sample& sample = samples[oldest_pending];
    if (sample.state == SAMPLE_PENDING) {
      if (now - sample.send_time < timeout) {
        return;  // everything after this was sent later still
      }
      // The loss is filed at the time the packet was SENT, like the JS
      // version, so it lands in the column where the packet went out.
      sample.state = SAMPLE_LOST;
      version++;
    }
    oldest_pending++;
  }
}

size_t TargetHistory::first_index_at_or_after(double time) const {
  size_t low = 0;
  size_t high = samples.size();
  while (low < high) {
    size_t middle = low + (high - low) / 2;
    if (samples[middle].send_time < time) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  return low;
}

const std::vector<Sample>& TargetHistory::get_samples() const {
  return samples;
}

const std::string& TargetHistory::get_address() const {
  return address;
}

const std::string& TargetHistory::get_name() const {
  return name;
}

const std::string& TargetHistory::get_status() const {
  return status;
}

uint64_t TargetHistory::get_version() const {
  return version;
}

int TargetHistory::get_flow_count() const {
  return flow_count;
}
