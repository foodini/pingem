// daemon.h - the heart of user_icmp: one thread, one poll() loop, and all of
// the daemon's state in one place.
//
// Each pass through the loop:
//
//   1. send every packet whose scheduled time has arrived
//   2. check on DNS lookups that were in flight
//   3. expire outstanding packets nobody answered
//   4. poll() on: the raw ICMP socket, both listening sockets, and every
//      client, with a timeout of "until the next scheduled packet"
//   5. drain the raw socket, matching replies to clients
//   6. read requests and commands from clients, flush pending output, and
//      accept new clients
//   7. close clients that hung up - and with them, their targets
//
// There are no callbacks and no locks. Nothing happens except in that order.
//
// Two kinds of client:
//
//   HTTP  - a browser EventSource on 127.0.0.1:<port> (pingem.html). One
//           request, one target, Server-Sent Events back. Kept until the GL
//           client makes the browser page obsolete.
//   LINE  - the Unix-domain-socket line protocol (shared/protocol.h): the GL
//           client, socat, and eventually boink. One connection can add and
//           remove any number of targets.
//
// Ownership:
//   Client     - one connection.
//   PendingAdd - a target waiting on DNS. Belongs to a client.
//   Target     - one thing being pinged. Belongs to a client. When a client
//                disconnects, everything it owns is destroyed immediately.

#ifndef USER_ICMP_DAEMON_H
#define USER_ICMP_DAEMON_H

#include "icmp_socket.h"
#include "packet_table.h"
#include "resolver.h"
#include "../shared/protocol.h"

#include <map>
#include <netinet/in.h>
#include <set>
#include <stdint.h>
#include <string>
#include <sys/types.h>
#include <vector>

struct DaemonConfig {
  int port;                    // TCP port on 127.0.0.1 (HTTP clients)
  double min_interval;         // clients asking for faster are clamped to this
  double reply_expiry;         // seconds before an unanswered packet is forgotten
  size_t max_client_backlog;   // bytes of unsent output before we drop a client
};

class Daemon {
public:
  Daemon(const DaemonConfig& config, IcmpSocket* icmp_socket, int tcp_listen_fd,
         int unix_listen_fd);
  void run();

private:
  enum ClientKind {
    HTTP_CLIENT,
    LINE_CLIENT
  };

  enum ClientState {
    READING_REQUEST,             // HTTP only: waiting for the request head
    ACTIVE,                      // HTTP: resolving or streaming. LINE: always.
    CLOSING                      // flush what's queued, then close
  };

  struct Client {
    int fd;
    ClientKind kind;
    ClientState state;
    uid_t uid;                   // LINE clients only (SO_PEERCRED); else -1
    std::string http_input;      // HTTP request head being accumulated
    LineBuffer line_input;       // LINE commands being accumulated
    std::string output;
    // The client's own ids for its targets -> our target ids. HTTP clients
    // have at most one, under client id 0.
    std::map<int, int> targets_by_client_id;
  };

  struct PendingAdd {
    int client_fd;
    int client_target_id;
    std::string name;
    double interval;
    int packet_size;
    int flows;                   // 0 = no flows (free checksum)
    ResolveRequest* request;
  };

  struct Target {
    int id;
    int client_fd;
    int client_target_id;        // the id the client uses for it
    std::string name;            // as the client gave it
    struct in_addr address;      // pinned at resolve time
    std::string address_text;
    uint16_t identifier;         // our ICMP identifier for this target
    uint64_t next_sequence;      // first packet is 1
    double interval;
    int packet_size;
    // Flows: ping n uses flow (n-1) % flows, and every packet in flow f is
    // sent with ICMP checksum flow_checksums[f]. flows == 0: free checksum.
    int flows;
    std::vector<uint16_t> flow_checksums;
    double next_send_time;       // monotonic
    int last_send_error;         // errno of the previous send, to avoid log spam
  };

  // Step 1: sending.
  void send_due_packets(double now);
  void send_one(Target* target);
  void schedule(Target* target);

  // Step 2: DNS and target lifetime.
  bool request_target(Client* client, int client_target_id, const std::string& name,
                      double interval, int packet_size, int flows, std::string* error);
  void check_resolutions();
  void start_target(PendingAdd* pending, Client* client, const struct in_addr& address);
  void destroy_target(Target* target);
  PendingAdd* find_pending(int client_fd, int client_target_id);
  void cancel_pending(PendingAdd* pending);
  uint16_t allocate_identifier();

  // Step 5: receiving.
  void drain_icmp_socket();

  // Events to clients, in whichever format the client speaks.
  void emit_ping(Target* target, uint64_t sequence, double send_time, int flow);
  void emit_reply(Target* target, uint64_t sequence, double receive_time, double rtt, int ttl,
                  const std::string& from, int flow);

  // Step 6: clients.
  void accept_clients(int listen_fd, ClientKind kind);
  void read_from_client(Client* client);
  void handle_http_request(Client* client, const std::string& head);
  void handle_line(Client* client, const std::string& line);
  void write_to_client(Client* client);
  void queue_output(Client* client, const std::string& data);
  void fail_http_client(Client* client, int status, const std::string& reason,
                        const std::string& body);

  // Step 7: teardown.
  void mark_for_close(Client* client);
  void close_marked_clients();

  double compute_poll_timeout(double now);   // seconds

  DaemonConfig config;
  IcmpSocket* icmp_socket;
  int tcp_listen_fd;
  int unix_listen_fd;
  PacketTable packet_table;
  Resolver resolver;

  std::map<int, Client*> clients;                 // by fd
  std::vector<PendingAdd*> pending_adds;
  std::map<int, Target*> targets;                 // by target id
  std::map<uint16_t, int> identifiers_in_use;     // identifier -> target id
  // When each target next sends, ordered by time. Exactly one entry per live
  // target. Entries for destroyed targets are harmless: when they come due,
  // the target id isn't in `targets` any more and they're simply dropped.
  std::multimap<double, int> schedule_by_time;
  std::set<int> clients_to_close;                 // fds

  int next_target_id;
  uint16_t next_identifier;
};

#endif
