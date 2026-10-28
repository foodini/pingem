#include "daemon_link.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

DaemonLink::DaemonLink(const std::vector<TargetSpec>& targets)
    : targets(targets), fd(-1), reported_disconnect(false), next_connect_attempt(0.0) {
}

DaemonLink::~DaemonLink() {
  if (fd >= 0) {
    close(fd);
  }
}

bool DaemonLink::is_connected() const {
  return fd >= 0;
}

bool DaemonLink::try_connect() {
  int new_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (new_fd < 0) {
    return false;
  }
  // Abstract namespace: leading NUL, then the name, and the address length
  // covers exactly that much. Must match the daemon's bind().
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  size_t name_length = strlen(USER_ICMP_SOCKET_NAME);
  memcpy(address.sun_path + 1, USER_ICMP_SOCKET_NAME, name_length);
  socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_length);

  // A Unix-socket connect() completes (or fails) immediately, so it's done
  // blocking; the socket is switched to non-blocking afterwards.
  if (connect(new_fd, (struct sockaddr*)&address, length) < 0) {
    close(new_fd);
    return false;
  }
  fcntl(new_fd, F_SETFL, fcntl(new_fd, F_GETFL) | O_NONBLOCK);

  fd = new_fd;
  input = LineBuffer();
  output.clear();
  for (size_t i = 0; i < targets.size(); i++) {
    output += format_add(targets[i].id, targets[i].host, targets[i].interval,
                         targets[i].packet_size, targets[i].flows);
  }
  return true;
}

void DaemonLink::disconnect(std::vector<LinkEvent>* events) {
  if (fd >= 0) {
    close(fd);
    fd = -1;
  }
  if (!reported_disconnect) {
    LinkEvent event;
    event.type = LINK_DISCONNECTED;
    event.id = -1;
    events->push_back(event);
    reported_disconnect = true;
  }
}

void DaemonLink::poll(double now, std::vector<LinkEvent>* events) {
  if (fd < 0) {
    if (now < next_connect_attempt) {
      return;
    }
    next_connect_attempt = now + 1.0;
    if (!try_connect()) {
      disconnect(events);   // reports DISCONNECTED once, the first time
      return;
    }
    reported_disconnect = false;
    LinkEvent event;
    event.type = LINK_CONNECTED;
    event.id = -1;
    events->push_back(event);
  }

  flush_output(events);
  if (fd < 0) {
    return;
  }

  char buffer[16384];
  while (true) {
    ssize_t length = recv(fd, buffer, sizeof(buffer), 0);
    if (length == 0) {
      disconnect(events);
      return;
    }
    if (length < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      if (errno == EINTR) {
        continue;
      }
      disconnect(events);
      return;
    }
    input.append(buffer, length);
  }

  std::string line;
  while (input.next_line(&line)) {
    handle_line(line, events);
  }
  if (input.overflowed()) {
    disconnect(events);
  }
}

void DaemonLink::flush_output(std::vector<LinkEvent>* events) {
  while (!output.empty() && fd >= 0) {
    ssize_t sent = send(fd, output.data(), output.size(), MSG_NOSIGNAL);
    if (sent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return;
      }
      if (errno == EINTR) {
        continue;
      }
      disconnect(events);
      return;
    }
    output.erase(0, sent);
  }
}

void DaemonLink::handle_line(const std::string& line, std::vector<LinkEvent>* events) {
  Message message;
  if (!parse_message(line, &message)) {
    return;
  }

  LinkEvent event;
  event.id = -1;
  event.seq = 0;
  event.time = 0.0;
  event.rtt = 0.0;
  event.ttl = 0;
  event.flow = -1;

  if (message.verb == "hello") {
    if (message.args.size() < 2 || atoi(message.args[1].c_str()) != PROTOCOL_VERSION) {
      event.type = LINK_ERROR;
      event.text = "user_icmp speaks a different protocol version: " + line;
      events->push_back(event);
    }
    return;
  }

  if (message.args.empty() || !parse_id(message.args[0], &event.id)) {
    if (message.verb == "error") {
      event.type = LINK_ERROR;
      event.text = message.text;
      events->push_back(event);
    }
    return;
  }

  if (message.verb == "ping") {
    event.type = LINK_PING;
    get_field(message, "flow", &event.flow);
    if (get_field(message, "seq", &event.seq) && get_field(message, "t", &event.time)) {
      events->push_back(event);
    }
  } else if (message.verb == "reply") {
    event.type = LINK_REPLY;
    if (get_field(message, "seq", &event.seq) && get_field(message, "t", &event.time) &&
        get_field(message, "rtt", &event.rtt)) {
      get_field(message, "ttl", &event.ttl);
      get_field(message, "from", &event.address);
      get_field(message, "flow", &event.flow);
      events->push_back(event);
    }
  } else if (message.verb == "added") {
    event.type = LINK_ADDED;
    if (message.args.size() >= 3) {
      event.address = message.args[2];
    }
    events->push_back(event);
  } else if (message.verb == "error") {
    event.type = LINK_ERROR;
    event.text = message.text;
    events->push_back(event);
  }
  // "removed" needs no action yet: the GUI never removes targets.
}
