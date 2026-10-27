// common.h - small helpers shared by every part of user_icmp: clocks, logging,
// and address formatting.
//
// Two clocks are used, deliberately:
//
//   * monotonic_now() - CLOCK_MONOTONIC. Never jumps (NTP, DST, the user setting
//     the date). Used for everything that is a *duration* or a *schedule*: when
//     the next packet goes out, RTTs, expiry of outstanding packets.
//
//   * realtime_now()  - CLOCK_REALTIME. Wall-clock time in seconds since the
//     epoch. Used ONLY for the timestamps we report to clients, because the UI
//     needs to place events on a calendar.
//
// Both are returned as double seconds. A double holds ~15-16 significant
// digits, so a realtime value (~1.8e9 s) keeps sub-microsecond resolution, which
// is far finer than anything we measure.

#ifndef USER_ICMP_COMMON_H
#define USER_ICMP_COMMON_H

#include <netinet/in.h>
#include <string>

double monotonic_now();
double realtime_now();

// "a.b.c.d" for an IPv4 address in network byte order.
std::string ipv4_to_string(const struct in_addr& address);

// printf-style logging to stdout with a wall-clock prefix. Kept deliberately
// dumb: the daemon is expected to run under systemd or in a terminal, and both
// capture stdout.
void log_message(const char* format, ...) __attribute__((format(printf, 1, 2)));

#endif
