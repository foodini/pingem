// packet_table.h - every echo request we've sent that hasn't been answered or
// expired yet.
//
// This replaces the old scheme of stuffing the 64-bit sequence number and the
// send timestamp into the packet body. The wire carries only a 16-bit
// identifier and a 16-bit sequence number; everything else about the packet is
// remembered here, keyed by those 32 bits.
//
// Uniqueness of the key:
//   * Each live target gets its own 16-bit identifier, so two targets never
//     share a key even if they're pinging the same address.
//   * Within a target, the 16-bit sequence number wraps every 65536 packets.
//     Entries expire after `expiry_seconds`, and the daemon enforces a minimum
//     interval, so as long as 65536 * min_interval > expiry_seconds a key can
//     never be in the table twice. With the defaults (0.1 s, 60 s) that's 6553
//     s vs 60 s. If it ever did happen, insert() overwrites the older entry,
//     which is the right call: the older packet is the one that's long lost.

#ifndef USER_ICMP_PACKET_TABLE_H
#define USER_ICMP_PACKET_TABLE_H

#include <map>
#include <stdint.h>

struct OutstandingPacket {
  int target_id;
  uint64_t full_sequence;    // the 64-bit sequence number the client sees
  int flow;                  // 0..K-1, or -1 if the target doesn't use flows
  double send_monotonic;     // for RTT
  double send_realtime;      // for reporting
};

class PacketTable {
public:
  explicit PacketTable(double expiry_seconds);

  void insert(uint16_t identifier, uint16_t sequence, const OutstandingPacket& packet);

  // Looks up and REMOVES the entry. Returns false if unknown (never ours,
  // already answered - i.e. a duplicate - or already expired).
  bool take(uint16_t identifier, uint16_t sequence, OutstandingPacket* packet);

  // Drops entries older than expiry_seconds. Cheap enough to call every loop.
  void expire(double now_monotonic);

  // Drops every entry belonging to a target that has gone away.
  void remove_target(int target_id);

  int size() const;

private:
  static uint32_t make_key(uint16_t identifier, uint16_t sequence);

  double expiry_seconds;
  std::map<uint32_t, OutstandingPacket> packets;
};

#endif
