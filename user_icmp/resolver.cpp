#include "resolver.h"

#include <string.h>
#include <sys/socket.h>

Resolver::Resolver() : live_count(0) {
}

Resolver::~Resolver() {
  for (size_t i = 0; i < parked.size(); i++) {
    gai_cancel(&parked[i]->control);
    // Can't safely free a request glibc might still write to; leaking at
    // process exit is harmless.
  }
}

ResolveRequest* Resolver::start(const std::string& name) {
  ResolveRequest* request = new ResolveRequest();
  request->name = name;
  memset(&request->hints, 0, sizeof(request->hints));
  request->hints.ai_family = AF_INET;          // IPv4 only, for now
  request->hints.ai_socktype = SOCK_RAW;       // one result per address, not per socket type
  memset(&request->control, 0, sizeof(request->control));
  request->control.ar_name = request->name.c_str();
  request->control.ar_request = &request->hints;

  struct gaicb* list[1];
  list[0] = &request->control;
  // GAI_NOWAIT + a NULL sigevent = "start it and don't notify me"; we poll
  // with gai_error() instead.
  if (getaddrinfo_a(GAI_NOWAIT, list, 1, NULL) != 0) {
    delete request;
    return NULL;
  }
  live_count++;
  return request;
}

bool Resolver::is_done(ResolveRequest* request) {
  return gai_error(&request->control) != EAI_INPROGRESS;
}

bool Resolver::get_result(ResolveRequest* request, struct in_addr* address, std::string* error) {
  int status = gai_error(&request->control);
  if (status != 0) {
    *error = gai_strerror(status);
    return false;
  }
  for (struct addrinfo* info = request->control.ar_result; info != NULL; info = info->ai_next) {
    if (info->ai_family == AF_INET) {
      *address = ((struct sockaddr_in*)info->ai_addr)->sin_addr;
      return true;
    }
  }
  *error = "no IPv4 address";
  return false;
}

void Resolver::free_request(ResolveRequest* request) {
  if (request->control.ar_result != NULL) {
    freeaddrinfo(request->control.ar_result);
  }
  delete request;
}

void Resolver::release(ResolveRequest* request) {
  live_count--;
  if (is_done(request)) {
    free_request(request);
    return;
  }
  if (gai_cancel(&request->control) == EAI_CANCELED) {
    free_request(request);
    return;
  }
  parked.push_back(request);
}

void Resolver::reap() {
  size_t i = 0;
  while (i < parked.size()) {
    if (is_done(parked[i])) {
      free_request(parked[i]);
      parked.erase(parked.begin() + i);
    } else {
      i++;
    }
  }
}

bool Resolver::has_pending() const {
  return live_count > 0 || !parked.empty();
}
