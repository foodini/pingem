#include "protocol.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

// ---------------------------------------------------------------------------
// LineBuffer
// ---------------------------------------------------------------------------

void LineBuffer::append(const char* data, size_t length) {
  buffer.append(data, length);
}

bool LineBuffer::next_line(std::string* line) {
  size_t newline = buffer.find('\n');
  if (newline == std::string::npos) {
    return false;
  }
  size_t end = newline;
  if (end > 0 && buffer[end - 1] == '\r') {
    end--;
  }
  *line = buffer.substr(0, end);
  buffer.erase(0, newline + 1);
  return true;
}

bool LineBuffer::overflowed() const {
  return buffer.find('\n') == std::string::npos && buffer.size() > MAX_LINE_LENGTH;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

bool parse_message(const std::string& line, Message* message) {
  message->verb.clear();
  message->args.clear();
  message->fields.clear();
  message->text.clear();

  std::vector<std::string> tokens;
  size_t start = 0;
  while (start < line.size()) {
    size_t space = line.find(' ', start);
    if (space == std::string::npos) {
      space = line.size();
    }
    if (space > start) {
      tokens.push_back(line.substr(start, space - start));
    }
    start = space + 1;
  }
  if (tokens.empty()) {
    return false;
  }

  message->verb = tokens[0];

  if (message->verb == "error") {
    // error <id> <free text...>
    if (tokens.size() >= 2) {
      message->args.push_back(tokens[1]);
      size_t text_start = line.find(tokens[1], message->verb.size()) + tokens[1].size();
      while (text_start < line.size() && line[text_start] == ' ') {
        text_start++;
      }
      message->text = line.substr(text_start);
    }
    return true;
  }

  for (size_t i = 1; i < tokens.size(); i++) {
    size_t equals = tokens[i].find('=');
    if (equals == std::string::npos) {
      message->args.push_back(tokens[i]);
    } else {
      message->fields[tokens[i].substr(0, equals)] = tokens[i].substr(equals + 1);
    }
  }
  return true;
}

static bool find_field(const Message& message, const std::string& key, std::string* value) {
  std::map<std::string, std::string>::const_iterator found = message.fields.find(key);
  if (found == message.fields.end()) {
    return false;
  }
  *value = found->second;
  return true;
}

bool get_field(const Message& message, const std::string& key, std::string* value) {
  return find_field(message, key, value);
}

bool get_field(const Message& message, const std::string& key, double* value) {
  std::string text;
  if (!find_field(message, key, &text) || text.empty()) {
    return false;
  }
  char* end = NULL;
  double parsed = strtod(text.c_str(), &end);
  if (*end != '\0') {
    return false;
  }
  *value = parsed;
  return true;
}

bool get_field(const Message& message, const std::string& key, uint64_t* value) {
  std::string text;
  if (!find_field(message, key, &text) || text.empty() || text[0] == '-') {
    return false;
  }
  char* end = NULL;
  unsigned long long parsed = strtoull(text.c_str(), &end, 10);
  if (*end != '\0') {
    return false;
  }
  *value = (uint64_t)parsed;
  return true;
}

bool get_field(const Message& message, const std::string& key, int* value) {
  std::string text;
  if (!find_field(message, key, &text) || text.empty()) {
    return false;
  }
  char* end = NULL;
  long parsed = strtol(text.c_str(), &end, 10);
  if (*end != '\0') {
    return false;
  }
  *value = (int)parsed;
  return true;
}

bool parse_id(const std::string& text, int* id) {
  if (text.empty() || text.size() > 9) {
    return false;
  }
  for (size_t i = 0; i < text.size(); i++) {
    if (text[i] < '0' || text[i] > '9') {
      return false;
    }
  }
  *id = atoi(text.c_str());
  return true;
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

std::string format_hello() {
  char line[64];
  snprintf(line, sizeof(line), "hello user_icmp %d\n", PROTOCOL_VERSION);
  return std::string(line);
}

std::string format_add(int id, const std::string& host, double interval, int size) {
  char line[MAX_LINE_LENGTH];
  snprintf(line, sizeof(line), "add %d %s interval=%g size=%d\n", id, host.c_str(), interval,
           size);
  return std::string(line);
}

std::string format_remove(int id) {
  char line[64];
  snprintf(line, sizeof(line), "remove %d\n", id);
  return std::string(line);
}

std::string format_added(int id, const std::string& host, const std::string& address) {
  char line[MAX_LINE_LENGTH];
  snprintf(line, sizeof(line), "added %d %s %s\n", id, host.c_str(), address.c_str());
  return std::string(line);
}

std::string format_removed(int id) {
  char line[64];
  snprintf(line, sizeof(line), "removed %d\n", id);
  return std::string(line);
}

std::string format_error(int id, const std::string& text) {
  char prefix[64];
  if (id < 0) {
    snprintf(prefix, sizeof(prefix), "error - ");
  } else {
    snprintf(prefix, sizeof(prefix), "error %d ", id);
  }
  // Keep the message on one line no matter what's in it.
  std::string clean = text;
  for (size_t i = 0; i < clean.size(); i++) {
    if (clean[i] == '\n' || clean[i] == '\r') {
      clean[i] = ' ';
    }
  }
  return std::string(prefix) + clean + "\n";
}

std::string format_ping(int id, uint64_t seq, double send_time) {
  char line[128];
  snprintf(line, sizeof(line), "ping %d seq=%" PRIu64 " t=%.6f\n", id, seq, send_time);
  return std::string(line);
}

std::string format_reply(int id, uint64_t seq, double receive_time, double rtt, int ttl,
                         const std::string& from) {
  char line[256];
  snprintf(line, sizeof(line), "reply %d seq=%" PRIu64 " t=%.6f rtt=%.9f ttl=%d from=%s\n", id,
           seq, receive_time, rtt, ttl, from.c_str());
  return std::string(line);
}
