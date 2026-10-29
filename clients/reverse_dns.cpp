#include "reverse_dns.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

ReverseDns::ReverseDns() : stopping(false) {
  worker = std::thread(&ReverseDns::run, this);
}

ReverseDns::~ReverseDns() {
  {
    std::lock_guard<std::mutex> lock(mutex);
    stopping = true;
    queue.clear();
  }
  wake.notify_one();
  worker.join();
}

bool ReverseDns::lookup(const std::string& address, std::string* name) {
  std::map<std::string, std::string>::iterator found = names.find(address);
  if (found != names.end()) {
    *name = found->second;
    return true;
  }
  if (requested.count(address) == 0) {
    requested[address] = true;
    {
      std::lock_guard<std::mutex> lock(mutex);
      queue.push_back(address);
    }
    wake.notify_one();
  }
  return false;
}

bool ReverseDns::poll() {
  std::vector<std::pair<std::string, std::string> > results;
  {
    std::lock_guard<std::mutex> lock(mutex);
    results.swap(finished);
  }
  for (size_t i = 0; i < results.size(); i++) {
    names[results[i].first] = results[i].second;
    requested.erase(results[i].first);
  }
  return !results.empty();
}

// The helper thread: take an address, look it up (this is the part that can
// block for seconds), hand the answer back.
void ReverseDns::run() {
  while (true) {
    std::string address;
    {
      std::unique_lock<std::mutex> lock(mutex);
      while (queue.empty() && !stopping) {
        wake.wait(lock);
      }
      if (stopping) {
        return;
      }
      address = queue.front();
      queue.pop_front();
    }

    std::string name;
    struct sockaddr_in socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sin_family = AF_INET;
    if (inet_pton(AF_INET, address.c_str(), &socket_address.sin_addr) == 1) {
      char host[NI_MAXHOST];
      // NI_NAMEREQD: fail rather than hand back the address as a "name".
      if (getnameinfo((struct sockaddr*)&socket_address, sizeof(socket_address), host,
                      sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
        name = host;
      }
    }

    std::lock_guard<std::mutex> lock(mutex);
    finished.push_back(std::make_pair(address, name));
  }
}
