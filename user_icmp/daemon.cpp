#include "daemon.h"

#include "common.h"

#include <errno.h>
#include <math.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

Daemon::Daemon(const DaemonConfig& config, IcmpSocket* icmp_socket, int listen_fd)
    : config(config),
      icmp_socket(icmp_socket),
      listen_fd(listen_fd),
      packet_table(config.reply_expiry),
      next_target_id(1) {
}

// ---------------------------------------------------------------------------
// The loop.
// ---------------------------------------------------------------------------

void Daemon::run() {
  log_message("user_icmp listening on @%s", USER_ICMP_SOCKET_NAME);

  std::vector<struct pollfd> poll_fds;
  // The fd of each client entry in poll_fds, parallel to it from index 2 on.
  std::vector<int> poll_client_fds;
  const size_t FIRST_CLIENT_INDEX = 2;

  while (true) {
    double now = monotonic_now();
    send_due_packets(now);
    check_resolutions();
    resolver.reap();
    expire_packets(now);
    close_marked_clients();

    poll_fds.clear();
    poll_client_fds.clear();

    struct pollfd entry;
    entry.revents = 0;
    entry.events = POLLIN;
    entry.fd = icmp_socket->get_fd();   // [0]
    poll_fds.push_back(entry);
    entry.fd = listen_fd;               // [1]
    poll_fds.push_back(entry);

    for (std::map<int, Client*>::iterator it = clients.begin(); it != clients.end(); ++it) {
      Client* client = it->second;
      entry.fd = client->fd;
      entry.events = POLLIN;
      if (!client->output.empty()) {
        entry.events |= POLLOUT;
      }
      poll_fds.push_back(entry);
      poll_client_fds.push_back(client->fd);
    }

    // ppoll rather than poll: it takes a timespec, so packets go out within
    // microseconds of their scheduled time instead of within a millisecond.
    double timeout = compute_poll_timeout(monotonic_now());
    struct timespec timeout_spec;
    timeout_spec.tv_sec = (time_t)timeout;
    timeout_spec.tv_nsec = (long)((timeout - (double)timeout_spec.tv_sec) * 1e9);

    int ready = ppoll(&poll_fds[0], poll_fds.size(), &timeout_spec, NULL);
    if (ready < 0) {
      if (errno != EINTR) {
        log_message("ppoll failed: %s", strerror(errno));
      }
      continue;
    }
    if (ready == 0) {
      continue;
    }

    if (poll_fds[0].revents & POLLIN) {
      drain_icmp_socket();
    }

    for (size_t i = 0; i < poll_client_fds.size(); i++) {
      short revents = poll_fds[i + FIRST_CLIENT_INDEX].revents;
      if (revents == 0) {
        continue;
      }
      std::map<int, Client*>::iterator found = clients.find(poll_client_fds[i]);
      if (found == clients.end()) {
        continue;
      }
      Client* client = found->second;
      if (revents & (POLLIN | POLLHUP | POLLERR)) {
        read_from_client(client);
      }
      if (revents & POLLOUT) {
        write_to_client(client);
      }
    }

    if (poll_fds[1].revents & POLLIN) {
      accept_clients();
    }
  }
}

double Daemon::compute_poll_timeout(double now) {
  // Wake at least once a second so expiry and housekeeping keep running even
  // when nothing is scheduled.
  double timeout = 1.0;
  if (!schedule_by_time.empty()) {
    double until_next = schedule_by_time.begin()->first - now;
    if (until_next < timeout) {
      timeout = until_next;
    }
  }
  if (!probe_schedule_by_time.empty()) {
    double until_next = probe_schedule_by_time.begin()->first - now;
    if (until_next < timeout) {
      timeout = until_next;
    }
  }
  // getaddrinfo_a gives us no file descriptor to poll, so while a lookup is in
  // flight we check back every 20 ms.
  if (resolver.has_pending() && timeout > 0.020) {
    timeout = 0.020;
  }
  if (timeout < 0.0) {
    timeout = 0.0;
  }
  return timeout;
}

// ---------------------------------------------------------------------------
// Step 1: sending.
// ---------------------------------------------------------------------------

void Daemon::send_due_packets(double now) {
  while (!schedule_by_time.empty() && schedule_by_time.begin()->first <= now) {
    int target_id = schedule_by_time.begin()->second;
    schedule_by_time.erase(schedule_by_time.begin());

    std::map<int, Target*>::iterator found = targets.find(target_id);
    if (found == targets.end()) {
      continue;  // target went away after it was scheduled
    }
    Target* target = found->second;
    send_one(target);
    schedule(target);
  }

  while (!probe_schedule_by_time.empty() && probe_schedule_by_time.begin()->first <= now) {
    double due = probe_schedule_by_time.begin()->first;
    int target_id = probe_schedule_by_time.begin()->second;
    probe_schedule_by_time.erase(probe_schedule_by_time.begin());

    std::map<int, Target*>::iterator found = targets.find(target_id);
    if (found == targets.end()) {
      continue;
    }
    Target* target = found->second;
    if (target->next_probe_time != due) {
      continue;  // stale: the probe rate changed after this was queued
    }
    send_probe(target);
    schedule_probe(target);
  }
}

void Daemon::send_one(Target* target) {
  uint64_t full_sequence = target->next_sequence++;
  int flow = -1;
  int fixed_checksum = -1;
  int slot = 0;   // which identifier and wire counter
  if (target->flows > 0) {
    flow = (int)((full_sequence - 1) % (uint64_t)target->flows);
    fixed_checksum = target->flow_checksums[flow];
    slot = flow;
  }
  uint16_t identifier = target->flow_identifiers[slot];
  uint16_t wire_sequence = target->flow_wire_sequence[slot]++;

  OutstandingPacket packet;
  packet.target_id = target->id;
  packet.full_sequence = full_sequence;
  packet.flow = flow;
  packet.send_realtime = realtime_now();
  packet.send_monotonic = monotonic_now();

  packet.is_probe = false;
  packet.ttl = 0;

  int error = icmp_socket->send_echo(target->address, identifier, wire_sequence,
                                     target->packet_size, fixed_checksum, 0);
  if (error != target->last_send_error) {
    if (error != 0) {
      log_message("target %d (%s): send failing: %s", target->id, target->name.c_str(),
                  strerror(error));
    } else {
      log_message("target %d (%s): sending again", target->id, target->name.c_str());
    }
    target->last_send_error = error;
  }

  // Recorded even if sendto() failed. No reply will ever match it, so it will
  // expire, and the client - which gets the "ping" event either way - will
  // count it as lost. A dead network should look like loss, not like silence.
  packet_table.insert(identifier, wire_sequence, packet);
  emit_ping(target, full_sequence, packet.send_realtime, flow);
}

void Daemon::schedule(Target* target) {
  // Advance by exactly one interval from the previous *scheduled* time, not
  // from "now", so scheduling jitter doesn't accumulate into drift.
  target->next_send_time += target->interval;

  // If we've fallen behind (the machine was suspended, or the loop stalled),
  // skip forward by whole intervals rather than firing a catch-up burst.
  // Bursts are exactly what we must never send: back-to-back packets can fill a
  // queue somewhere on the path and cause the very loss we're trying to
  // measure.
  double now = monotonic_now();
  if (target->next_send_time < now) {
    double behind = now - target->next_send_time;
    double skips = ceil(behind / target->interval);
    target->next_send_time += skips * target->interval;
  }

  schedule_by_time.insert(std::make_pair(target->next_send_time, target->id));
}

// Route probes.
//
// A probe is just an echo request with a small TTL, sent on one of the
// target's flow checksums so that it follows exactly the path that flow's
// pings take (this is the "Paris traceroute" idea: classic traceroute varies
// the very header fields load balancers hash on, so its hops can come from
// different paths and stitch together into a route that doesn't exist).
//
// Probing never bursts. Probes are spread evenly between the pings - with R
// probes per interval, at 1/2R, 3/2R, 5/2R ... of the way from one ping to
// the next - so the target sees a steady trickle and the pings themselves
// stay undisturbed.

int Daemon::probe_limit(Target* target, int flow) {
  int known = target->destination_ttl[flow];
  return known > 0 ? known : MAX_PROBE_TTL;
}

void Daemon::set_probe_rate(Target* target, double rate) {
  if (!(rate > 0.0) || target->flows == 0) {
    rate = 0.0;
  }
  if (rate > MAX_PROBE_RATE) {
    rate = MAX_PROBE_RATE;
  }
  // The probes alone must not go faster than the fastest allowed ping rate.
  if (rate > 0.0 && target->interval / rate < config.min_interval) {
    rate = target->interval / config.min_interval;
  }
  target->probe_rate = rate;
  if (rate == 0.0) {
    target->next_probe_time = -1.0;   // any queued entry is now stale
    return;
  }
  double period = target->interval / rate;
  double gap = period < target->interval ? period : target->interval;
  // next_send_time is the next ping; the first probe goes half a gap after.
  target->next_probe_time = target->next_send_time + gap / 2.0;
  probe_schedule_by_time.insert(std::make_pair(target->next_probe_time, target->id));
}

void Daemon::schedule_probe(Target* target) {
  if (target->probe_rate <= 0.0) {
    target->next_probe_time = -1.0;
    return;
  }
  double period = target->interval / target->probe_rate;
  target->next_probe_time += period;
  double now = monotonic_now();
  if (target->next_probe_time < now) {
    double skips = ceil((now - target->next_probe_time) / period);
    target->next_probe_time += skips * period;
  }
  probe_schedule_by_time.insert(std::make_pair(target->next_probe_time, target->id));
}

void Daemon::send_probe(Target* target) {
  // Find the next (flow, ttl) in the rotation that's worth probing: every
  // flow at TTL 1, every flow at TTL 2, ... skipping TTLs beyond where a
  // flow is known to reach the target. TTL 1 is always worth probing, so
  // this always finds something.
  int highest = 1;
  for (int f = 0; f < target->flows; f++) {
    int limit = probe_limit(target, f);
    if (limit > highest) {
      highest = limit;
    }
  }
  if (target->probe_ttl < 1 || target->probe_ttl > highest) {
    target->probe_flow = 0;
    target->probe_ttl = 1;
  }
  while (target->probe_ttl > probe_limit(target, target->probe_flow)) {
    target->probe_flow++;
    if (target->probe_flow >= target->flows) {
      target->probe_flow = 0;
      target->probe_ttl++;
      if (target->probe_ttl > highest) {
        target->probe_ttl = 1;
      }
    }
  }
  int flow = target->probe_flow;
  int ttl = target->probe_ttl;

  // Advance for next time.
  target->probe_flow++;
  if (target->probe_flow >= target->flows) {
    target->probe_flow = 0;
    target->probe_ttl++;
  }

  // On the wire, exactly like this flow's pings except for the TTL - and
  // numbered from the same counter, so the two never collide.
  uint16_t identifier = target->flow_identifiers[flow];
  uint16_t wire_sequence = target->flow_wire_sequence[flow]++;

  OutstandingPacket packet;
  packet.target_id = target->id;
  packet.full_sequence = 0;   // probes aren't numbered for the client
  packet.flow = flow;
  packet.is_probe = true;
  packet.ttl = ttl;
  packet.send_realtime = realtime_now();
  packet.send_monotonic = monotonic_now();

  // A failed send just becomes a "*" hop after the timeout. The ping path
  // already logs a dead network; no need to say it twice.
  icmp_socket->send_echo(target->address, identifier, wire_sequence,
                         target->packet_size, target->flow_checksums[flow], ttl);
  packet_table.insert(identifier, wire_sequence, packet);
}

// ---------------------------------------------------------------------------
// Step 2: DNS and target lifetime.
// ---------------------------------------------------------------------------

// Host names and dotted quads only: letters, digits, '.', '-'.
static bool is_plausible_host(const std::string& name) {
  if (name.empty() || name.size() > 253) {
    return false;
  }
  for (size_t i = 0; i < name.size(); i++) {
    char c = name[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-';
    if (!ok) {
      return false;
    }
  }
  return true;
}

// Validates a request for a new target and starts resolving it. On failure,
// returns false with *error set.
bool Daemon::request_target(Client* client, int client_target_id, const std::string& name,
                            double interval, int packet_size, int flows, double probe_rate,
                            std::string* error) {
  if (!is_plausible_host(name)) {
    *error = "bad address";
    return false;
  }
  if (!(interval > 0.0) || isinf(interval)) {
    *error = "bad interval";
    return false;
  }
  if (flows < 0 || flows > MAX_FLOWS) {
    *error = "bad flows";
    return false;
  }
  if (!(probe_rate >= 0.0) || isinf(probe_rate)) {
    *error = "bad probes";
    return false;
  }
  if (probe_rate > 0.0 && flows == 0) {
    *error = "probes need flows";
    return false;
  }
  if (client->targets_by_client_id.count(client_target_id) != 0 ||
      find_pending(client->fd, client_target_id) != NULL) {
    *error = "id already in use";
    return false;
  }
  if (interval < config.min_interval) {
    log_message("client %d: interval %.4fs raised to the minimum %.4fs", client->fd, interval,
                config.min_interval);
    interval = config.min_interval;
  }
  if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
  if (packet_size > MAX_PACKET_SIZE) packet_size = MAX_PACKET_SIZE;

  ResolveRequest* request = resolver.start(name);
  if (request == NULL) {
    *error = "resolver unavailable";
    return false;
  }

  PendingAdd* pending = new PendingAdd();
  pending->client_fd = client->fd;
  pending->client_target_id = client_target_id;
  pending->name = name;
  pending->interval = interval;
  pending->packet_size = packet_size;
  pending->flows = flows;
  pending->probe_rate = probe_rate;
  pending->request = request;
  pending_adds.push_back(pending);
  return true;
}

void Daemon::check_resolutions() {
  size_t i = 0;
  while (i < pending_adds.size()) {
    PendingAdd* pending = pending_adds[i];
    if (!resolver.is_done(pending->request)) {
      i++;
      continue;
    }
    pending_adds.erase(pending_adds.begin() + i);

    struct in_addr address;
    std::string error;
    bool ok = resolver.get_result(pending->request, &address, &error);
    resolver.release(pending->request);

    std::map<int, Client*>::iterator found = clients.find(pending->client_fd);
    if (found != clients.end() && clients_to_close.count(pending->client_fd) == 0) {
      Client* client = found->second;
      if (ok) {
        start_target(pending, client, address);
      } else {
        log_message("client %d: cannot resolve '%s': %s", client->fd, pending->name.c_str(),
                    error.c_str());
        std::string message = "cannot resolve " + pending->name + ": " + error;
        queue_output(client, format_error(pending->client_target_id, message));
      }
    }
    delete pending;
  }
}

Daemon::PendingAdd* Daemon::find_pending(int client_fd, int client_target_id) {
  for (size_t i = 0; i < pending_adds.size(); i++) {
    if (pending_adds[i]->client_fd == client_fd &&
        pending_adds[i]->client_target_id == client_target_id) {
      return pending_adds[i];
    }
  }
  return NULL;
}

void Daemon::cancel_pending(PendingAdd* pending) {
  for (size_t i = 0; i < pending_adds.size(); i++) {
    if (pending_adds[i] == pending) {
      pending_adds.erase(pending_adds.begin() + i);
      break;
    }
  }
  resolver.release(pending->request);
  delete pending;
}

// A random identifier no live target is using. Random rather than counting
// up, for the same reason the flow checksums are random: a load balancer
// hashing identifiers with something simple could put a run of consecutive
// values all in one bucket, hiding the paths we're looking for. (And two
// daemons, or a restarted one with replies still in flight, are unlikely to
// collide.)
uint16_t Daemon::allocate_identifier() {
  while (true) {
    uint16_t identifier = (uint16_t)(lrand48() & 0xffff);
    if (identifiers_in_use.count(identifier) == 0) {
      return identifier;
    }
  }
}

void Daemon::start_target(PendingAdd* pending, Client* client, const struct in_addr& address) {
  Target* target = new Target();
  target->id = next_target_id++;
  target->client_fd = client->fd;
  target->client_target_id = pending->client_target_id;
  target->name = pending->name;
  target->address = address;
  target->address_text = ipv4_to_string(address);
  target->next_sequence = 1;
  target->interval = pending->interval;
  target->packet_size = pending->packet_size;
  target->last_send_error = 0;

  // One fixed checksum per flow. The values themselves don't matter - only
  // that they're distinct - but they must look random: real routers hash
  // with simple functions (XOR folds, CRCs), and a regular pattern of
  // checksums (an arithmetic progression, say) can land every flow in the
  // same hash bucket, hiding the very paths we're trying to find. So: random
  // values, no duplicates, and never 0x0000 or 0xffff, which are both "zero"
  // in ones-complement arithmetic.
  target->flows = pending->flows;
  while ((int)target->flow_checksums.size() < target->flows) {
    uint16_t value = (uint16_t)(lrand48() & 0xffff);
    if (value == 0x0000 || value == 0xffff) {
      continue;
    }
    bool duplicate = false;
    for (size_t i = 0; i < target->flow_checksums.size(); i++) {
      if (target->flow_checksums[i] == value) {
        duplicate = true;
      }
    }
    if (!duplicate) {
      target->flow_checksums.push_back(value);
    }
  }

  // Stagger the first packet by a random fraction of the interval (at most a
  // second). Clients tend to add all their targets at the same instant;
  // without this every target would fire in the same millisecond, forever.
  double stagger_window = target->interval < 1.0 ? target->interval : 1.0;
  target->next_send_time = monotonic_now() + 0.01 + drand48() * stagger_window;

  // One identifier per flow (or just one without flows), each claimed at
  // once so the next can't repeat it, and a wire sequence counter for each,
  // starting anywhere.
  int slots = target->flows > 0 ? target->flows : 1;
  for (int slot = 0; slot < slots; slot++) {
    uint16_t identifier = allocate_identifier();
    target->flow_identifiers.push_back(identifier);
    target->flow_wire_sequence.push_back((uint16_t)(lrand48() & 0xffff));
    identifiers_in_use[identifier] = target->id;
  }

  // Probing state.
  target->probe_rate = 0.0;
  target->next_probe_time = -1.0;
  target->probe_flow = 0;
  target->probe_ttl = 1;
  target->destination_ttl.assign(target->flows, 0);

  targets[target->id] = target;
  set_probe_rate(target, pending->probe_rate);
  client->targets_by_client_id[target->client_target_id] = target->id;
  schedule_by_time.insert(std::make_pair(target->next_send_time, target->id));

  queue_output(client,
               format_added(target->client_target_id, target->name, target->address_text));

  log_message("client %d: target %d %s (%s) interval=%.3fs size=%d flows=%d probes=%g",
              client->fd, target->id, target->name.c_str(), target->address_text.c_str(),
              target->interval, target->packet_size, target->flows, target->probe_rate);
}

void Daemon::destroy_target(Target* target) {
  log_message("client %d: target %d (%s) stopped after %llu packets", target->client_fd,
              target->id, target->name.c_str(), (unsigned long long)(target->next_sequence - 1));
  std::map<int, Client*>::iterator client_it = clients.find(target->client_fd);
  if (client_it != clients.end()) {
    client_it->second->targets_by_client_id.erase(target->client_target_id);
  }
  for (size_t slot = 0; slot < target->flow_identifiers.size(); slot++) {
    identifiers_in_use.erase(target->flow_identifiers[slot]);
  }
  packet_table.remove_target(target->id);
  // Its entry in schedule_by_time is left to fall out on its own.
  targets.erase(target->id);
  delete target;
}

// ---------------------------------------------------------------------------
// Steps 3 and 5: receiving, and giving up waiting.
// ---------------------------------------------------------------------------

void Daemon::drain_icmp_socket() {
  while (true) {
    IcmpMessage message;
    if (!icmp_socket->receive_message(&message)) {
      if (icmp_socket->is_drained()) {
        return;
      }
      continue;  // consumed something that wasn't ours; keep going
    }

    // Echo replies and errors both identify OUR packet by the identifier and
    // sequence we sent (an error quotes the start of the packet it's about).
    OutstandingPacket packet;
    if (!packet_table.take(message.identifier, message.sequence, &packet)) {
      // Unknown: a duplicate, something that arrived after expiry, a reply
      // to another user_icmp instance (it shares our magic string), or an
      // error about somebody else's ping.
      continue;
    }

    std::map<int, Target*>::iterator target_it = targets.find(packet.target_id);
    if (target_it == targets.end()) {
      continue;
    }
    if (packet.is_probe) {
      handle_probe_answer(target_it->second, packet, message);
    } else {
      handle_ping_answer(target_it->second, packet, message);
    }
  }
}

void Daemon::handle_ping_answer(Target* target, const OutstandingPacket& packet,
                                const IcmpMessage& message) {
  std::string from = ipv4_to_string(message.source);
  if (message.kind == ICMP_ECHO_REPLY) {
    double rtt = message.receive_monotonic - packet.send_monotonic;
    emit_reply(target, packet.full_sequence, message.receive_realtime, rtt, message.ttl, from,
               packet.flow);
    return;
  }
  // An error about a ping: it was refused, not lost. Tell the client now
  // rather than let it time out, so it can say who refused it and why.
  emit_line(target, format_unreachable(target->client_target_id, packet.full_sequence,
                                       message.receive_realtime, from, message.error_type,
                                       message.error_code, packet.flow));
}

void Daemon::handle_probe_answer(Target* target, const OutstandingPacket& packet,
                                 const IcmpMessage& message) {
  int flow = packet.flow;
  if (flow < 0 || flow >= target->flows) {
    return;
  }
  double rtt = message.receive_monotonic - packet.send_monotonic;
  std::string from = ipv4_to_string(message.source);
  int& destination_ttl = target->destination_ttl[flow];

  if (message.kind == ICMP_ECHO_REPLY || message.error_type == 3) {
    // The probe got as far as it can go: to the target (echo reply), or to
    // a router that says it can't be delivered (Destination Unreachable).
    // Either way there's nothing to learn by probing this flow further, so
    // that's where its rotation stops - from now on, until it changes.
    if (destination_ttl == 0 || packet.ttl < destination_ttl) {
      destination_ttl = packet.ttl;
    }
    bool reached = message.kind == ICMP_ECHO_REPLY;
    emit_line(target, format_hop(target->client_target_id, flow, packet.ttl,
                                 packet.send_realtime, rtt, from, reached,
                                 reached ? -1 : message.error_code));
    return;
  }

  // Time Exceeded: a router on the way. If this was a probe at the TTL we
  // thought reached the target, the path has got longer - forget what we
  // knew and probe further again.
  if (destination_ttl != 0 && packet.ttl >= destination_ttl) {
    destination_ttl = 0;
  }
  emit_line(target, format_hop(target->client_target_id, flow, packet.ttl, packet.send_realtime,
                               rtt, from, false, -1));
}

void Daemon::expire_packets(double now) {
  std::vector<OutstandingPacket> expired_probes;
  packet_table.expire(now, config.probe_timeout, &expired_probes);
  for (size_t i = 0; i < expired_probes.size(); i++) {
    const OutstandingPacket& packet = expired_probes[i];
    std::map<int, Target*>::iterator target_it = targets.find(packet.target_id);
    if (target_it == targets.end()) {
      continue;
    }
    Target* target = target_it->second;
    emit_line(target, format_hop(target->client_target_id, packet.flow, packet.ttl,
                                 packet.send_realtime, -1.0, "*", false, -1));
  }
}

// ---------------------------------------------------------------------------
// Events to clients.
// ---------------------------------------------------------------------------

void Daemon::emit_line(Target* target, const std::string& line) {
  std::map<int, Client*>::iterator found = clients.find(target->client_fd);
  if (found == clients.end()) {
    return;
  }
  queue_output(found->second, line);
}

void Daemon::emit_ping(Target* target, uint64_t sequence, double send_time, int flow) {
  std::map<int, Client*>::iterator found = clients.find(target->client_fd);
  if (found == clients.end()) {
    return;
  }
  queue_output(found->second,
               format_ping(target->client_target_id, sequence, send_time, flow));
}

void Daemon::emit_reply(Target* target, uint64_t sequence, double receive_time, double rtt,
                        int ttl, const std::string& from, int flow) {
  std::map<int, Client*>::iterator found = clients.find(target->client_fd);
  if (found == clients.end()) {
    return;
  }
  queue_output(found->second, format_reply(target->client_target_id, sequence, receive_time,
                                           rtt, ttl, from, flow));
}

// ---------------------------------------------------------------------------
// Step 6: clients.
// ---------------------------------------------------------------------------

void Daemon::accept_clients() {
  while (true) {
    int fd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        log_message("accept failed: %s", strerror(errno));
      }
      return;
    }
    Client* client = new Client();
    client->fd = fd;
    client->state = ACTIVE;
    client->uid = (uid_t)-1;
    clients[fd] = client;

    // The kernel tells us exactly who is on the other end of a Unix socket.
    // Not used for anything yet beyond logging; it's what per-user limits
    // will hang off.
    struct ucred credentials;
    socklen_t length = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0) {
      client->uid = credentials.uid;
    }
    log_message("client %d: connected (uid %d)", fd, (int)client->uid);
    queue_output(client, format_hello());
  }
}

void Daemon::read_from_client(Client* client) {
  char buffer[4096];
  while (true) {
    ssize_t length = recv(client->fd, buffer, sizeof(buffer), 0);
    if (length == 0) {
      // The client closed the connection (it quit, or crashed). This is the
      // moment its targets die.
      mark_for_close(client);
      return;
    }
    if (length < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return;
      }
      if (errno == EINTR) {
        continue;
      }
      mark_for_close(client);
      return;
    }
    if (client->state == CLOSING) {
      continue;  // draining; ignore anything more
    }

    client->input.append(buffer, length);
    std::string line;
    while (client->input.next_line(&line)) {
      handle_line(client, line);
    }
    if (client->input.overflowed()) {
      queue_output(client, format_error(-1, "line too long"));
      client->state = CLOSING;
      write_to_client(client);
      return;
    }
  }
}

void Daemon::handle_line(Client* client, const std::string& line) {
  Message message;
  if (!parse_message(line, &message)) {
    return;  // blank line; ignore
  }

  if (message.verb == "add") {
    // add <id> <host> [interval=S] [size=N] [flows=K] [probes=R]
    int id;
    if (message.args.size() != 2 || !parse_id(message.args[0], &id)) {
      queue_output(client, format_error(-1, "usage: add <id> <host> [interval=S] [size=N] "
                                            "[flows=K] [probes=R]"));
      return;
    }
    double interval = 1.0;
    int size = 64;
    if (message.fields.count("interval") != 0 && !get_field(message, "interval", &interval)) {
      queue_output(client, format_error(id, "bad interval"));
      return;
    }
    if (message.fields.count("size") != 0 && !get_field(message, "size", &size)) {
      queue_output(client, format_error(id, "bad size"));
      return;
    }
    int flows = 0;
    if (message.fields.count("flows") != 0 && !get_field(message, "flows", &flows)) {
      queue_output(client, format_error(id, "bad flows"));
      return;
    }
    double probes = 0.0;
    if (message.fields.count("probes") != 0 && !get_field(message, "probes", &probes)) {
      queue_output(client, format_error(id, "bad probes"));
      return;
    }
    std::string error;
    if (!request_target(client, id, message.args[1], interval, size, flows, probes, &error)) {
      queue_output(client, format_error(id, error));
    }
    return;
  }

  if (message.verb == "probe") {
    // probe <id> rate=R
    int id;
    double rate;
    if (message.args.size() != 1 || !parse_id(message.args[0], &id) ||
        !get_field(message, "rate", &rate) || !(rate >= 0.0) || isinf(rate)) {
      queue_output(client, format_error(-1, "usage: probe <id> rate=R"));
      return;
    }
    std::map<int, int>::iterator found = client->targets_by_client_id.find(id);
    if (found != client->targets_by_client_id.end()) {
      std::map<int, Target*>::iterator target_it = targets.find(found->second);
      if (target_it != targets.end()) {
        if (rate > 0.0 && target_it->second->flows == 0) {
          queue_output(client, format_error(id, "probes need flows"));
        } else {
          set_probe_rate(target_it->second, rate);
        }
        return;
      }
    }
    PendingAdd* pending = find_pending(client->fd, id);
    if (pending != NULL) {
      // Still resolving: it'll start at this rate.
      pending->probe_rate = rate;
      return;
    }
    queue_output(client, format_error(id, "no such id"));
    return;
  }

  if (message.verb == "remove") {
    int id;
    if (message.args.size() != 1 || !parse_id(message.args[0], &id)) {
      queue_output(client, format_error(-1, "usage: remove <id>"));
      return;
    }
    std::map<int, int>::iterator found = client->targets_by_client_id.find(id);
    if (found != client->targets_by_client_id.end()) {
      std::map<int, Target*>::iterator target_it = targets.find(found->second);
      if (target_it != targets.end()) {
        destroy_target(target_it->second);
      }
      queue_output(client, format_removed(id));
      return;
    }
    PendingAdd* pending = find_pending(client->fd, id);
    if (pending != NULL) {
      cancel_pending(pending);
      queue_output(client, format_removed(id));
      return;
    }
    queue_output(client, format_error(id, "no such id"));
    return;
  }

  queue_output(client, format_error(-1, "unknown command: " + message.verb));
}

void Daemon::queue_output(Client* client, const std::string& data) {
  if (clients_to_close.count(client->fd) != 0) {
    return;  // already on its way out
  }
  client->output += data;
  if (client->output.size() > config.max_client_backlog) {
    // The client isn't reading. Rather than buffer without limit, give up on
    // it.
    log_message("client %d: not reading (%zu bytes queued); dropping", client->fd,
                client->output.size());
    client->output.clear();
    mark_for_close(client);
    return;
  }
  write_to_client(client);
}

void Daemon::write_to_client(Client* client) {
  while (!client->output.empty()) {
    ssize_t sent = send(client->fd, client->output.data(), client->output.size(), MSG_NOSIGNAL);
    if (sent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return;  // poll() will tell us when there's room
      }
      if (errno == EINTR) {
        continue;
      }
      client->output.clear();
      mark_for_close(client);
      return;
    }
    client->output.erase(0, sent);
  }
  if (client->state == CLOSING) {
    mark_for_close(client);
  }
}

// ---------------------------------------------------------------------------
// Step 7: teardown.
// ---------------------------------------------------------------------------

void Daemon::mark_for_close(Client* client) {
  clients_to_close.insert(client->fd);
}

void Daemon::close_marked_clients() {
  for (std::set<int>::iterator it = clients_to_close.begin(); it != clients_to_close.end(); ++it) {
    std::map<int, Client*>::iterator found = clients.find(*it);
    if (found == clients.end()) {
      continue;
    }
    Client* client = found->second;

    // Everything the client owns goes with it.
    size_t i = 0;
    while (i < pending_adds.size()) {
      if (pending_adds[i]->client_fd == client->fd) {
        cancel_pending(pending_adds[i]);   // erases element i
      } else {
        i++;
      }
    }
    while (!client->targets_by_client_id.empty()) {
      int target_id = client->targets_by_client_id.begin()->second;
      std::map<int, Target*>::iterator target_it = targets.find(target_id);
      if (target_it != targets.end()) {
        destroy_target(target_it->second);   // also erases the map entry
      } else {
        client->targets_by_client_id.erase(client->targets_by_client_id.begin());
      }
    }

    log_message("client %d: closed", client->fd);
    close(client->fd);
    clients.erase(found);
    delete client;
  }
  clients_to_close.clear();
}
