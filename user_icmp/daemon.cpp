#include "daemon.h"

#include "common.h"
#include "http.h"

#include <errno.h>
#include <math.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

Daemon::Daemon(const DaemonConfig& config, IcmpSocket* icmp_socket, int tcp_listen_fd,
               int unix_listen_fd)
    : config(config),
      icmp_socket(icmp_socket),
      tcp_listen_fd(tcp_listen_fd),
      unix_listen_fd(unix_listen_fd),
      packet_table(config.reply_expiry),
      next_target_id(1) {
  // Start identifiers at a random point so two daemons (or a daemon restarted
  // while old replies are still in flight) are unlikely to collide.
  next_identifier = (uint16_t)(lrand48() & 0xffff);
}

// ---------------------------------------------------------------------------
// The loop.
// ---------------------------------------------------------------------------

void Daemon::run() {
  log_message("user_icmp listening on 127.0.0.1:%d and @%s", config.port,
              USER_ICMP_SOCKET_NAME);

  std::vector<struct pollfd> poll_fds;
  // The fd of each client entry in poll_fds, parallel to it from index 3 on.
  std::vector<int> poll_client_fds;
  const size_t FIRST_CLIENT_INDEX = 3;

  while (true) {
    double now = monotonic_now();
    send_due_packets(now);
    check_resolutions();
    resolver.reap();
    packet_table.expire(now);
    close_marked_clients();

    poll_fds.clear();
    poll_client_fds.clear();

    struct pollfd entry;
    entry.revents = 0;
    entry.events = POLLIN;
    entry.fd = icmp_socket->get_fd();   // [0]
    poll_fds.push_back(entry);
    entry.fd = tcp_listen_fd;           // [1]
    poll_fds.push_back(entry);
    entry.fd = unix_listen_fd;          // [2]
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
      accept_clients(tcp_listen_fd, HTTP_CLIENT);
    }
    if (poll_fds[2].revents & POLLIN) {
      accept_clients(unix_listen_fd, LINE_CLIENT);
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
}

void Daemon::send_one(Target* target) {
  uint64_t full_sequence = target->next_sequence++;
  uint16_t wire_sequence = (uint16_t)(full_sequence & 0xffff);
  int flow = -1;
  int fixed_checksum = -1;
  if (target->flows > 0) {
    flow = (int)((full_sequence - 1) % (uint64_t)target->flows);
    fixed_checksum = target->flow_checksums[flow];
  }

  OutstandingPacket packet;
  packet.target_id = target->id;
  packet.full_sequence = full_sequence;
  packet.flow = flow;
  packet.send_realtime = realtime_now();
  packet.send_monotonic = monotonic_now();

  int error = icmp_socket->send_echo(target->address, target->identifier, wire_sequence,
                                     target->packet_size, fixed_checksum);
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
  packet_table.insert(target->identifier, wire_sequence, packet);
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

// Validates a request for a new target and starts resolving it. Used by both
// client kinds. On failure, returns false with *error set.
bool Daemon::request_target(Client* client, int client_target_id, const std::string& name,
                            double interval, int packet_size, int flows,
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
        if (client->kind == HTTP_CLIENT) {
          fail_http_client(client, 502, "Bad Gateway", message + "\n");
        } else {
          queue_output(client, format_error(pending->client_target_id, message));
        }
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

uint16_t Daemon::allocate_identifier() {
  while (identifiers_in_use.count(next_identifier) != 0) {
    next_identifier++;
  }
  uint16_t identifier = next_identifier;
  next_identifier++;
  return identifier;
}

void Daemon::start_target(PendingAdd* pending, Client* client, const struct in_addr& address) {
  Target* target = new Target();
  target->id = next_target_id++;
  target->client_fd = client->fd;
  target->client_target_id = pending->client_target_id;
  target->name = pending->name;
  target->address = address;
  target->address_text = ipv4_to_string(address);
  target->identifier = allocate_identifier();
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

  targets[target->id] = target;
  identifiers_in_use[target->identifier] = target->id;
  client->targets_by_client_id[target->client_target_id] = target->id;
  schedule_by_time.insert(std::make_pair(target->next_send_time, target->id));

  if (client->kind == HTTP_CLIENT) {
    queue_output(client, make_event_stream_headers());
  } else {
    queue_output(client, format_added(target->client_target_id, target->name,
                                      target->address_text));
  }

  log_message("client %d: target %d %s (%s) interval=%.3fs size=%d flows=%d id=%u", client->fd,
              target->id, target->name.c_str(), target->address_text.c_str(), target->interval,
              target->packet_size, target->flows, (unsigned)target->identifier);
}

void Daemon::destroy_target(Target* target) {
  log_message("client %d: target %d (%s) stopped after %llu packets", target->client_fd,
              target->id, target->name.c_str(), (unsigned long long)(target->next_sequence - 1));
  std::map<int, Client*>::iterator client_it = clients.find(target->client_fd);
  if (client_it != clients.end()) {
    client_it->second->targets_by_client_id.erase(target->client_target_id);
  }
  identifiers_in_use.erase(target->identifier);
  packet_table.remove_target(target->id);
  // Its entry in schedule_by_time is left to fall out on its own.
  targets.erase(target->id);
  delete target;
}

// ---------------------------------------------------------------------------
// Step 5: receiving.
// ---------------------------------------------------------------------------

void Daemon::drain_icmp_socket() {
  while (true) {
    EchoReply reply;
    if (!icmp_socket->receive_echo_reply(&reply)) {
      if (icmp_socket->is_drained()) {
        return;
      }
      continue;  // consumed something that wasn't ours; keep going
    }

    OutstandingPacket packet;
    if (!packet_table.take(reply.identifier, reply.sequence, &packet)) {
      // Unknown: a duplicate, something that arrived after expiry, or a reply
      // to another user_icmp instance (it shares our magic string).
      continue;
    }

    std::map<int, Target*>::iterator target_it = targets.find(packet.target_id);
    if (target_it == targets.end()) {
      continue;
    }

    double rtt = reply.receive_monotonic - packet.send_monotonic;
    emit_reply(target_it->second, packet.full_sequence, reply.receive_realtime, rtt, reply.ttl,
               ipv4_to_string(reply.source), packet.flow);
  }
}

// ---------------------------------------------------------------------------
// Events to clients.
// ---------------------------------------------------------------------------

void Daemon::emit_ping(Target* target, uint64_t sequence, double send_time, int flow) {
  std::map<int, Client*>::iterator found = clients.find(target->client_fd);
  if (found == clients.end()) {
    return;
  }
  Client* client = found->second;
  if (client->kind == HTTP_CLIENT) {
    queue_output(client, make_ping_event(target->address_text, sequence, send_time));
  } else {
    queue_output(client, format_ping(target->client_target_id, sequence, send_time, flow));
  }
}

void Daemon::emit_reply(Target* target, uint64_t sequence, double receive_time, double rtt,
                        int ttl, const std::string& from, int flow) {
  std::map<int, Client*>::iterator found = clients.find(target->client_fd);
  if (found == clients.end()) {
    return;
  }
  Client* client = found->second;
  if (client->kind == HTTP_CLIENT) {
    queue_output(client, make_reply_event(from, sequence, receive_time, rtt, ttl));
  } else {
    queue_output(client,
                 format_reply(target->client_target_id, sequence, receive_time, rtt, ttl, from,
                              flow));
  }
}

// ---------------------------------------------------------------------------
// Step 6: clients.
// ---------------------------------------------------------------------------

void Daemon::accept_clients(int listen_fd, ClientKind kind) {
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
    client->kind = kind;
    client->uid = (uid_t)-1;
    clients[fd] = client;

    if (kind == HTTP_CLIENT) {
      client->state = READING_REQUEST;
    } else {
      client->state = ACTIVE;
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
}

void Daemon::read_from_client(Client* client) {
  char buffer[4096];
  while (true) {
    ssize_t length = recv(client->fd, buffer, sizeof(buffer), 0);
    if (length == 0) {
      // The client closed the connection (tab closed, client quit). This is
      // the moment its targets die.
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

    if (client->kind == HTTP_CLIENT) {
      if (client->state != READING_REQUEST) {
        continue;  // nothing more is expected from a browser; ignore it
      }
      client->http_input.append(buffer, length);
      if (client->http_input.size() > MAX_REQUEST_HEAD) {
        fail_http_client(client, 431, "Request Header Fields Too Large", "request too large\n");
        return;
      }
      size_t head_end = find_end_of_head(client->http_input);
      if (head_end != 0) {
        std::string head = client->http_input.substr(0, head_end);
        client->http_input.clear();
        handle_http_request(client, head);
      }
    } else {
      client->line_input.append(buffer, length);
      std::string line;
      while (client->line_input.next_line(&line)) {
        handle_line(client, line);
      }
      if (client->line_input.overflowed()) {
        queue_output(client, format_error(-1, "line too long"));
        client->state = CLOSING;
        write_to_client(client);
        return;
      }
    }
  }
}

void Daemon::handle_http_request(Client* client, const std::string& head) {
  HttpRequest request;
  if (!parse_request(head, &request)) {
    fail_http_client(client, 400, "Bad Request", "malformed request\n");
    return;
  }
  if (request.method != "GET") {
    fail_http_client(client, 405, "Method Not Allowed", "GET only\n");
    return;
  }
  if (request.path != "/") {
    fail_http_client(client, 404, "Not Found", "not found\n");
    return;
  }

  std::string name = "8.8.8.8";
  double interval = 1.0;
  int packet_size = 64;

  for (std::map<std::string, std::string>::iterator it = request.query.begin();
       it != request.query.end(); ++it) {
    const std::string& key = it->first;
    const std::string& value = it->second;
    if (key == "address") {
      name = value;
    } else if (key == "interval") {
      char* end = NULL;
      interval = strtod(value.c_str(), &end);
      if (end == value.c_str() || *end != '\0') {
        fail_http_client(client, 400, "Bad Request", "bad interval\n");
        return;
      }
    } else if (key == "packet_size") {
      char* end = NULL;
      long size = strtol(value.c_str(), &end, 10);
      if (end == value.c_str() || *end != '\0') {
        fail_http_client(client, 400, "Bad Request", "bad packet_size\n");
        return;
      }
      packet_size = size > 65535 ? 65535 : (int)size;
    } else {
      fail_http_client(client, 404, "Not Found", "unknown parameter: " + key + "\n");
      return;
    }
  }

  std::string error;
  if (!request_target(client, 0, name, interval, packet_size, 0, &error)) {
    fail_http_client(client, error == "resolver unavailable" ? 503 : 400,
                     error == "resolver unavailable" ? "Service Unavailable" : "Bad Request",
                     error + "\n");
    return;
  }
  client->state = ACTIVE;
}

void Daemon::handle_line(Client* client, const std::string& line) {
  Message message;
  if (!parse_message(line, &message)) {
    return;  // blank line; ignore
  }

  if (message.verb == "add") {
    // add <id> <host> [interval=S] [size=N] [flows=K]
    int id;
    if (message.args.size() != 2 || !parse_id(message.args[0], &id)) {
      queue_output(client,
                   format_error(-1, "usage: add <id> <host> [interval=S] [size=N] [flows=K]"));
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
    std::string error;
    if (!request_target(client, id, message.args[1], interval, size, flows, &error)) {
      queue_output(client, format_error(id, error));
    }
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

void Daemon::fail_http_client(Client* client, int status, const std::string& reason,
                              const std::string& body) {
  // EventSource treats any non-200 response as fatal and does NOT reconnect,
  // which is what we want for a bad request.
  client->state = CLOSING;
  client->output += make_error_response(status, reason, body);
  write_to_client(client);
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
