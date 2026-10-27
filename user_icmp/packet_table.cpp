#include "packet_table.h"

PacketTable::PacketTable(double expiry_seconds) : expiry_seconds(expiry_seconds) {
}

uint32_t PacketTable::make_key(uint16_t identifier, uint16_t sequence) {
  return ((uint32_t)identifier << 16) | sequence;
}

void PacketTable::insert(uint16_t identifier, uint16_t sequence, const OutstandingPacket& packet) {
  packets[make_key(identifier, sequence)] = packet;
}

bool PacketTable::take(uint16_t identifier, uint16_t sequence, OutstandingPacket* packet) {
  std::map<uint32_t, OutstandingPacket>::iterator found =
      packets.find(make_key(identifier, sequence));
  if (found == packets.end()) {
    return false;
  }
  *packet = found->second;
  packets.erase(found);
  return true;
}

void PacketTable::expire(double now_monotonic) {
  // A linear scan. The table holds roughly (send rate * expiry) entries - a
  // few hundred in normal use - so this is not worth anything cleverer.
  std::map<uint32_t, OutstandingPacket>::iterator it = packets.begin();
  while (it != packets.end()) {
    if (now_monotonic - it->second.send_monotonic > expiry_seconds) {
      packets.erase(it++);
    } else {
      ++it;
    }
  }
}

void PacketTable::remove_target(int target_id) {
  std::map<uint32_t, OutstandingPacket>::iterator it = packets.begin();
  while (it != packets.end()) {
    if (it->second.target_id == target_id) {
      packets.erase(it++);
    } else {
      ++it;
    }
  }
}

int PacketTable::size() const {
  return (int)packets.size();
}
