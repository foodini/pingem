// reverse_dns.h - names for router addresses, looked up in the background.
//
// The route graph labels each router with the domain that owns it
// ("comcast.net"), which means a reverse DNS lookup per router. Those can take
// seconds, and the drawing loop must never wait, so lookups run on one helper
// thread: the main loop asks for a name, gets "not yet", and a later frame
// finds it in the cache. This is the client's only thread; it shares nothing
// with the main loop but a queue and a list of answers, both behind one
// mutex.
//
// Each address is looked up once per run. An address with no PTR record is
// remembered as having no name.

#ifndef PINGEM_REVERSE_DNS_H
#define PINGEM_REVERSE_DNS_H

#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

class ReverseDns {
public:
  ReverseDns();
  ~ReverseDns();   // stops the thread (waiting for a lookup in progress)

  // Main thread. If `address` has been looked up, returns true with *name
  // set (empty if it has no name). Otherwise queues it, if it isn't queued
  // already, and returns false.
  bool lookup(const std::string& address, std::string* name);

  // Main thread, once per frame: collects finished lookups. Returns true if
  // there were any, so views that show names know to redraw.
  bool poll();

private:
  void run();

  // Main thread only.
  std::map<std::string, std::string> names;   // finished
  std::map<std::string, bool> requested;      // queued or in progress

  // Shared, under `mutex`.
  std::mutex mutex;
  std::condition_variable wake;
  std::deque<std::string> queue;
  std::vector<std::pair<std::string, std::string> > finished;
  bool stopping;

  std::thread worker;
};

#endif
