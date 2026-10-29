#include "route_store.h"

// Enough (flow, TTL) slots for every flow and every TTL the daemon allows.
static const int FLOW_SLOTS = 64;
static const int TTL_SLOTS = 32;

RouteStore::RouteStore() : last_answer(FLOW_SLOTS * TTL_SLOTS, -1), version(0) {
}

int RouteStore::intern(const std::string& address) {
  std::map<std::string, int>::iterator found = address_index.find(address);
  if (found != address_index.end()) {
    return found->second;
  }
  int index = (int)addresses.size();
  addresses.push_back(address);
  address_index[address] = index;
  return index;
}

void RouteStore::on_hop(int flow, int ttl, double send_time, double rtt,
                        const std::string& address, bool reached, int code) {
  if (flow < 0 || flow > 127 || ttl < 1 || ttl > 255) {
    return;
  }
  HopObservation observation;
  observation.send_time = send_time;
  observation.flow = (int8_t)flow;
  observation.ttl = (uint8_t)ttl;
  observation.code = -1;
  if (rtt < 0.0 || address == "*") {
    observation.kind = HOP_SILENT;
    observation.rtt = 0.0f;
    observation.router = -1;
  } else {
    observation.rtt = (float)rtt;
    observation.router = intern(address);
    if (reached) {
      observation.kind = HOP_REACHED;
    } else if (code >= 0) {
      observation.kind = HOP_UNREACHABLE;
      observation.code = (int8_t)code;
    } else {
      observation.kind = HOP_ROUTER;
    }
  }

  // A different answer than last time at this (flow, TTL) is a route change.
  // Refusals and silence aren't answers about the path.
  if ((observation.kind == HOP_ROUTER || observation.kind == HOP_REACHED) && flow < FLOW_SLOTS &&
      ttl < TTL_SLOTS) {
    int answer = observation.router * 2 + (observation.kind == HOP_REACHED ? 1 : 0);
    int& last = last_answer[flow * TTL_SLOTS + ttl];
    if (last >= 0 && last != answer) {
      size_t at = change_times.size();
      while (at > 0 && change_times[at - 1] > send_time) {
        at--;
      }
      change_times.insert(change_times.begin() + at, send_time);
    }
    last = answer;
  }

  // Insert in send-time order, searching back from the end.
  size_t position = observations.size();
  while (position > 0 && observations[position - 1].send_time > send_time) {
    position--;
  }
  observations.insert(observations.begin() + position, observation);
  version++;
}

const std::vector<HopObservation>& RouteStore::get_observations() const {
  return observations;
}

size_t RouteStore::first_index_at_or_after(double time) const {
  size_t low = 0;
  size_t high = observations.size();
  while (low < high) {
    size_t middle = low + (high - low) / 2;
    if (observations[middle].send_time < time) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  return low;
}

const std::vector<double>& RouteStore::get_change_times() const {
  return change_times;
}

int RouteStore::get_router_count() const {
  return (int)addresses.size();
}

const std::string& RouteStore::get_router_address(int router) const {
  return addresses[router];
}

uint64_t RouteStore::get_version() const {
  return version;
}
