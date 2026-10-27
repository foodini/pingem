#include "http.h"

#include <inttypes.h>
#include <stdio.h>

size_t find_end_of_head(const std::string& buffer) {
  size_t position = buffer.find("\r\n\r\n");
  if (position == std::string::npos) {
    return 0;
  }
  return position + 4;
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Decodes %XX escapes and '+' (space). Returns false on a bad escape.
static bool url_decode(const std::string& in, std::string* out) {
  out->clear();
  for (size_t i = 0; i < in.size(); i++) {
    char c = in[i];
    if (c == '+') {
      out->push_back(' ');
    } else if (c == '%') {
      if (i + 2 >= in.size()) {
        return false;
      }
      int high = hex_value(in[i + 1]);
      int low = hex_value(in[i + 2]);
      if (high < 0 || low < 0) {
        return false;
      }
      out->push_back((char)(high * 16 + low));
      i += 2;
    } else {
      out->push_back(c);
    }
  }
  return true;
}

bool parse_request(const std::string& head, HttpRequest* request) {
  // Request line: METHOD SP TARGET SP VERSION CRLF
  size_t line_end = head.find("\r\n");
  if (line_end == std::string::npos) {
    return false;
  }
  std::string line = head.substr(0, line_end);
  size_t first_space = line.find(' ');
  if (first_space == std::string::npos) {
    return false;
  }
  size_t second_space = line.find(' ', first_space + 1);
  if (second_space == std::string::npos) {
    return false;
  }
  request->method = line.substr(0, first_space);
  std::string target = line.substr(first_space + 1, second_space - first_space - 1);

  size_t question = target.find('?');
  request->path = target.substr(0, question);
  request->query.clear();
  if (question == std::string::npos) {
    return true;
  }

  // name=value&name=value...
  std::string query_string = target.substr(question + 1);
  size_t start = 0;
  while (start <= query_string.size()) {
    size_t ampersand = query_string.find('&', start);
    if (ampersand == std::string::npos) {
      ampersand = query_string.size();
    }
    std::string pair = query_string.substr(start, ampersand - start);
    if (!pair.empty()) {
      size_t equals = pair.find('=');
      std::string raw_name = pair.substr(0, equals);
      std::string raw_value = (equals == std::string::npos) ? "" : pair.substr(equals + 1);
      std::string name;
      std::string value;
      if (!url_decode(raw_name, &name) || !url_decode(raw_value, &value)) {
        return false;
      }
      request->query[name] = value;
    }
    start = ampersand + 1;
  }
  return true;
}

std::string make_error_response(int status, const std::string& reason, const std::string& body) {
  char line[128];
  snprintf(line, sizeof(line), "HTTP/1.1 %d %s\r\n", status, reason.c_str());
  std::string response(line);
  response += "Content-Type: text/plain\r\n";
  response += "Access-Control-Allow-Origin: *\r\n";
  response += "Connection: close\r\n";
  char length[64];
  snprintf(length, sizeof(length), "Content-Length: %zu\r\n\r\n", body.size());
  response += length;
  response += body;
  return response;
}

std::string make_event_stream_headers() {
  // Same headers user_icmp2.py sent. Allow-Origin * is what lets a page opened
  // from file:// talk to us at all.
  return std::string(
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/event-stream\r\n"
      "Cache-Control: no-cache\r\n"
      "Connection: keep-alive\r\n"
      "Access-Control-Allow-Credentials: true\r\n"
      "Access-Control-Allow-Origin: *\r\n"
      "\r\n");
}

std::string make_ping_event(const std::string& to, uint64_t icmp_seq, double timestamp) {
  char buffer[256];
  snprintf(buffer, sizeof(buffer),
           "data: {\"type\":\"ping\", \"to\":\"%s\", \"icmp_seq\":%" PRIu64
           ", \"timestamp\":%.6f}\n\n",
           to.c_str(), icmp_seq, timestamp);
  return std::string(buffer);
}

std::string make_reply_event(const std::string& from, uint64_t icmp_seq, double timestamp,
                             double rtt, int ttl) {
  char buffer[256];
  snprintf(buffer, sizeof(buffer),
           "data: {\"type\":\"reply\", \"from\":\"%s\", \"icmp_seq\":%" PRIu64
           ", \"timestamp\":%.6f, \"rtt\":%.9f, \"ttl\":%d}\n\n",
           from.c_str(), icmp_seq, timestamp, rtt, ttl);
  return std::string(buffer);
}
