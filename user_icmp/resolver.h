// resolver.h - non-blocking name -> IPv4 address lookups via glibc's
// getaddrinfo_a().
//
// Why: the daemon is a single poll() loop. A plain getaddrinfo() can block for
// seconds on a slow DNS server, and while it blocks no pings go out - which
// would show up in every graph as a gap or a burst of fake latency.
//
// How it's used (polling, no callbacks, no signals):
//
//     ResolveRequest* request = resolver.start("example.com");
//     ...each pass through the main loop...
//     if (resolver.is_done(request)) {
//       struct in_addr address;
//       std::string error;
//       if (resolver.get_result(request, &address, &error)) { ... }
//       resolver.release(request);
//     }
//
// Note for the paranoid: glibc implements getaddrinfo_a() with its own helper
// threads. Our code never sees them; they run after privileges are dropped.
//
// Reverse lookups (address -> name, for labelling traceroute hops) are NOT
// handled here: glibc has no async getnameinfo(). That will be a small,
// separate resolver thread when route probing arrives.

#ifndef USER_ICMP_RESOLVER_H
#define USER_ICMP_RESOLVER_H

#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <vector>

struct ResolveRequest {
  std::string name;          // must outlive the lookup; gaicb points into it
  struct addrinfo hints;
  struct gaicb control;
};

class Resolver {
public:
  Resolver();
  ~Resolver();

  // Starts a lookup. Returns NULL if glibc refused to queue it.
  ResolveRequest* start(const std::string& name);

  bool is_done(ResolveRequest* request);

  // Only valid once is_done() is true. Picks the FIRST IPv4 address and pins
  // the target to it, so a name with several addresses (amazon.com) doesn't
  // get a different machine on every packet.
  bool get_result(ResolveRequest* request, struct in_addr* address, std::string* error);

  // Frees a finished request. For a request that is still in flight (the
  // client hung up mid-lookup), cancels it if possible; if glibc can't cancel
  // it, it's parked and freed later by reap().
  void release(ResolveRequest* request);

  // Frees parked requests that have since finished. Call once per loop.
  void reap();

  // True if any lookup (live or parked) is outstanding, so the main loop knows
  // it must wake up periodically to check on them.
  bool has_pending() const;

private:
  void free_request(ResolveRequest* request);

  int live_count;
  std::vector<ResolveRequest*> parked;
};

#endif
