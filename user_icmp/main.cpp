// main.cpp - user_icmp: sends and receives ICMP echo on behalf of unprivileged
// local clients (the pingem GL client, and eventually "boink").
//
// Startup order matters for security:
//
//   1. Open the raw ICMP socket.          (needs root / CAP_NET_RAW)
//   2. Open the listening socket.         (@user_icmp; needs nothing)
//   3. Drop privileges for good.          setgroups / setgid / setuid, then
//                                         clear every capability
//   4. Run the loop.                      everything else - the protocol
//                                         parser, DNS, all client input -
//                                         runs unprivileged.
//
// The raw socket survives step 3 because privilege is checked when a socket is
// created, not each time it's used.
//
// Two ways to start it, and step 3 covers both:
//   sudo ./user_icmp          root: switch to --user (default nobody), which
//                             also clears all capabilities.
//   setcap cap_net_raw+ep     you: no user to switch, but the process holds
//                             CAP_NET_RAW, so it's cleared explicitly.
// Either way, step 3 ends by proving it can't open another raw socket.

#include "common.h"
#include "daemon.h"
#include "icmp_socket.h"
#include "../shared/protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static void usage(const char* program) {
  fprintf(stderr,
          "usage: %s [options]\n"
          "  --user NAME         user to run as after startup (default nobody)\n"
          "  --min-interval S    smallest per-target interval allowed, seconds (default 0.1)\n"
          "  --reply-expiry S    forget unanswered packets after S seconds (default 60)\n"
          "  --help\n",
          program);
}

// The Unix domain socket for line-protocol clients, in the Linux "abstract
// namespace": the name starts with a NUL byte, so there is no file on disk -
// nothing to chmod, nothing stale left behind after a crash. It disappears
// when we exit. Any local user can connect; the daemon learns who each one is
// from SO_PEERCRED.
static int open_unix_listen_socket(const char* name) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  size_t name_length = strlen(name);
  if (name_length + 1 > sizeof(address.sun_path)) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  address.sun_path[0] = '\0';
  memcpy(address.sun_path + 1, name, name_length);
  // For abstract sockets the length passed to bind() is significant: it must
  // cover exactly the leading NUL plus the name, no trailing padding.
  socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_length);
  if (bind(fd, (struct sockaddr*)&address, length) < 0 || listen(fd, 16) < 0) {
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
}

// Empties all three capability sets (effective, permitted, inheritable) -
// and with permitted empty, the kernel empties the ambient set too. Done with
// the raw capset() system call so we don't need libcap.
static bool clear_capabilities() {
  struct __user_cap_header_struct header;
  struct __user_cap_data_struct data[2];   // version 3 uses two
  memset(&header, 0, sizeof(header));
  memset(data, 0, sizeof(data));
  header.version = _LINUX_CAPABILITY_VERSION_3;
  header.pid = 0;   // this process
  return syscall(SYS_capset, &header, data) == 0;
}

// The proof that step 3 worked: we must no longer be able to do the one
// privileged thing we ever did.
static bool can_open_raw_socket() {
  int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
  if (fd < 0) {
    return false;
  }
  close(fd);
  return true;
}

static bool switch_user(const char* user_name);

// Returns false if privileges could not be dropped COMPLETELY. In that case
// we refuse to run at all.
static bool drop_privileges(const char* user_name) {
  if (geteuid() == 0 && !switch_user(user_name)) {
    return false;
  }
  // Root or not: shed every capability. (Started via setcap, this is where
  // CAP_NET_RAW goes. After switching away from root they're already gone,
  // and this changes nothing.)
  if (!clear_capabilities()) {
    perror("user_icmp: capset");
    return false;
  }
  // And make sure nothing we might ever exec could regain privilege.
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

  if (can_open_raw_socket()) {
    fprintf(stderr, "user_icmp: still able to open raw sockets after dropping privileges; "
                    "exiting\n");
    return false;
  }
  return true;
}

// Root only: become `user_name` for good.
static bool switch_user(const char* user_name) {
  struct passwd* user = getpwnam(user_name);
  if (user == NULL) {
    fprintf(stderr, "user_icmp: no such user '%s'\n", user_name);
    return false;
  }
  if (user->pw_uid == 0) {
    fprintf(stderr, "user_icmp: refusing to run as root ('%s' has uid 0)\n", user_name);
    return false;
  }

  // Order matters: supplementary groups and gid while we still can, uid last.
  if (setgroups(0, NULL) < 0) {
    perror("user_icmp: setgroups");
    return false;
  }
  if (setgid(user->pw_gid) < 0) {
    perror("user_icmp: setgid");
    return false;
  }
  if (setuid(user->pw_uid) < 0) {
    perror("user_icmp: setuid");
    return false;
  }

  // Belt and braces: prove we can't get root back.
  if (setuid(0) == 0) {
    fprintf(stderr, "user_icmp: privilege drop did not stick; exiting\n");
    return false;
  }
  return true;
}

int main(int argc, char* argv[]) {
  DaemonConfig config;
  config.min_interval = 0.1;
  config.reply_expiry = 60.0;
  config.probe_timeout = 3.0;
  config.max_client_backlog = 4 * 1024 * 1024;
  const char* user_name = "nobody";

  static struct option long_options[] = {
      {"user", required_argument, NULL, 'u'},
      {"min-interval", required_argument, NULL, 'm'},
      {"reply-expiry", required_argument, NULL, 'e'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0}};

  while (true) {
    int option = getopt_long(argc, argv, "", long_options, NULL);
    if (option == -1) {
      break;
    }
    switch (option) {
      case 'u':
        user_name = optarg;
        break;
      case 'm':
        config.min_interval = atof(optarg);
        break;
      case 'e':
        config.reply_expiry = atof(optarg);
        break;
      default:
        usage(argv[0]);
        return option == 'h' ? 0 : 2;
    }
  }
  if (config.min_interval <= 0.0 || config.reply_expiry <= 0.0) {
    usage(argv[0]);
    return 2;
  }
  // See packet_table.h: the 16-bit sequence must not wrap within the expiry.
  if (65536.0 * config.min_interval <= config.reply_expiry) {
    fprintf(stderr, "user_icmp: --reply-expiry must be less than 65536 * --min-interval\n");
    return 2;
  }

  // Writes to a client that just vanished must return EPIPE, not kill us.
  signal(SIGPIPE, SIG_IGN);
  srand48((long)time(NULL) ^ (long)getpid());

  // ---- Step 1: open the raw ICMP socket. Still root (or CAP_NET_RAW). ----
  IcmpSocket icmp_socket;
  if (!icmp_socket.open_socket()) {
    fprintf(stderr, "user_icmp: cannot open raw ICMP socket: %s\n", strerror(errno));
    fprintf(stderr, "  (run as root, or grant CAP_NET_RAW with setcap)\n");
    return 1;
  }

  // ---- Step 2: open the listening socket @user_icmp. Still privileged, ----
  // ---- but it doesn't need to be.                                       ----
  int listen_fd = open_unix_listen_socket(USER_ICMP_SOCKET_NAME);
  if (listen_fd < 0) {
    fprintf(stderr, "user_icmp: cannot listen on @%s: %s\n", USER_ICMP_SOCKET_NAME,
            strerror(errno));
    fprintf(stderr, "  (is another user_icmp already running?)\n");
    return 1;
  }

  // ---- Step 3: drop privileges for good. Nothing below this line runs ----
  // ---- as root, and nothing above it has read any outside input.      ----
  if (!drop_privileges(user_name)) {
    return 1;
  }
  log_message("running as uid %d gid %d", (int)getuid(), (int)getgid());

  // ---- Step 4: run the loop (see daemon.h). Never returns. ----
  Daemon daemon(config, &icmp_socket, listen_fd);
  daemon.run();
  return 0;
}
