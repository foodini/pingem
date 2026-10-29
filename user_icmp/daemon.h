// daemon.h - the heart of user_icmp: one thread, one poll() loop, and all of
// the daemon's state in one place.
//
// Each pass through the loop:
//
//   1. send every packet (ping or route probe) whose time has arrived
//   2. check on DNS lookups that were in flight
//   3. expire outstanding packets nobody answered - for a probe, that is
//      itself an answer: a "*" hop
//   4. poll() on: the raw ICMP socket, the listening socket, and every
//      client, with a timeout of "until the next scheduled packet"
//   5. drain the raw socket, matching replies to clients
//   6. read commands from clients, flush pending output, and accept new
//      clients
//   7. close clients that hung up - and with them, their targets
//
// There are no callbacks and no locks. Nothing happens except in that order.
//
// Clients connect over the Unix domain socket @user_icmp and speak the line
// protocol in shared/protocol.h: the GL client, socat, and eventually boink.
// One connection can add and remove any number of targets. (There used to be
// an HTTP/Server-Sent-Events interface for the browser page; it's gone.)
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
  double min_interval;         // clients asking for faster are clamped to this
  double reply_expiry;         // seconds before an unanswered packet is forgotten
  double probe_timeout;        // seconds before an unanswered probe becomes a "*" hop
  size_t max_client_backlog;   // bytes of unsent output before we drop a client
};

class Daemon {
public:
  Daemon(const DaemonConfig& config, IcmpSocket* icmp_socket, int listen_fd);
  void run();

private:
  enum ClientState {
    ACTIVE,
    CLOSING                      // flush what's queued, then close
  };

  struct Client {
    int fd;
    ClientState state;
    uid_t uid;                   // who's on the other end (SO_PEERCRED); -1 if unknown
    LineBuffer input;            // commands being accumulated
    std::string output;
    // The client's own ids for its targets -> our target ids.
    std::map<int, int> targets_by_client_id;
  };

  struct PendingAdd {
    int client_fd;
    int client_target_id;
    std::string name;
    double interval;
    int packet_size;
    int flows;                   // 0 = no flows (free checksum)
    double probe_rate;           // route probes per ping interval
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

    // Route probes: echo requests on the same flow checksums as the pings,
    // but with a small TTL, so the router where the TTL runs out answers
    // with Time Exceeded and reveals itself. They have their own identifier,
    // so a probe can never be mistaken for a ping (or counted as loss).
    //
    // They walk (flow, ttl) in rotation: every flow at TTL 1, then every
    // flow at TTL 2, ... up to where that flow reaches the target, then
    // around again.
    uint16_t probe_identifier;
    uint64_t next_probe_sequence;
    double probe_rate;           // probes per ping interval; 0 = none
    double next_probe_time;      // monotonic; < 0 when not probing
    int probe_flow;              // where the rotation is
    int probe_ttl;
    // The TTL at which each flow's probes reached the target (an echo reply,
    // or Destination Unreachable). 0 = not known yet: probe to MAX_PROBE_TTL.
    std::vector<int> destination_ttl;
  };

  // Step 1: sending.
  void send_due_packets(double now);
  void send_one(Target* target);
  void schedule(Target* target);
  void send_probe(Target* target);
  void schedule_probe(Target* target);
  void set_probe_rate(Target* target, double rate);
  int probe_limit(Target* target, int flow);   // highest TTL worth probing on a flow

  // Step 2: DNS and target lifetime.
  bool request_target(Client* client, int client_target_id, const std::string& name,
                      double interval, int packet_size, int flows, double probe_rate,
                      std::string* error);
  void check_resolutions();
  void start_target(PendingAdd* pending, Client* client, const struct in_addr& address);
  void destroy_target(Target* target);
  PendingAdd* find_pending(int client_fd, int client_target_id);
  void cancel_pending(PendingAdd* pending);
  uint16_t allocate_identifier();

  // Steps 3 and 5: receiving, and giving up waiting.
  void drain_icmp_socket();
  void handle_ping_answer(Target* target, const OutstandingPacket& packet,
                          const IcmpMessage& message);
  void handle_probe_answer(Target* target, const OutstandingPacket& packet,
                           const IcmpMessage& message);
  void expire_packets(double now);

  // Events to clients.
  void emit_ping(Target* target, uint64_t sequence, double send_time, int flow);
  void emit_reply(Target* target, uint64_t sequence, double receive_time, double rtt, int ttl,
                  const std::string& from, int flow);
  void emit_line(Target* target, const std::string& line);

  // Step 6: clients.
  void accept_clients();
  void read_from_client(Client* client);
  void handle_line(Client* client, const std::string& line);
  void write_to_client(Client* client);
  void queue_output(Client* client, const std::string& data);

  // Step 7: teardown.
  void mark_for_close(Client* client);
  void close_marked_clients();

  double compute_poll_timeout(double now);   // seconds

  DaemonConfig config;
  IcmpSocket* icmp_socket;
  int listen_fd;
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
  // The same for route probes, for targets that are probing. A stale entry
  // (the rate changed after it was queued) is recognised because its time no
  // longer matches the target's next_probe_time.
  std::multimap<double, int> probe_schedule_by_time;
  std::set<int> clients_to_close;                 // fds

  int next_target_id;
  uint16_t next_identifier;
};

#endif
