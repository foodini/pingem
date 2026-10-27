#include "common.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static double timespec_to_seconds(const struct timespec& ts) {
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

double monotonic_now() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return timespec_to_seconds(ts);
}

double realtime_now() {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return timespec_to_seconds(ts);
}

std::string ipv4_to_string(const struct in_addr& address) {
  char buffer[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == NULL) {
    return std::string("?.?.?.?");
  }
  return std::string(buffer);
}

void log_message(const char* format, ...) {
  time_t now = time(NULL);
  struct tm local;
  localtime_r(&now, &local);
  char stamp[32];
  strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &local);

  printf("%s ", stamp);
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
  printf("\n");
  fflush(stdout);
}
