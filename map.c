#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_HISTORY_MAP_PATH "/sys/fs/bpf/packet_history_map"
#define DEFAULT_BAN_MAP_PATH "/sys/fs/bpf/ip_ban_list"

struct packet_history_user
{
  __u32 lock;
  __u64 timestamp_sec;
  __u32 total_packet_count;
  __u32 total_packet_size;
};

struct ban_entry_user
{
  __u64 ban_until_sec;
};

static void ipv4_to_str(__u32 addr, char *buf, size_t size)
{
  if (!inet_ntop(AF_INET, &addr, buf, size)) {
    snprintf(buf, size, "<invalid>");
  }
}

static int open_map_or_print(const char *path)
{
  int fd = bpf_obj_get(path);
  if (fd < 0) {
    fprintf(stderr, "failed to open map: %s (%s)\n", path, strerror(errno));
  }
  return fd;
}

static void dump_packet_history_map(int map_fd)
{
  __u32 key;
  __u32 next_key;
  int has_prev = 0;

  puts("=== packet_history_map ===");
  puts("source_ip        timestamp_sec    packet_count    packet_size");

  while (bpf_map_get_next_key(map_fd, has_prev ? &key : NULL, &next_key) == 0) {
    struct packet_history_user v = {0};
    if (bpf_map_lookup_elem(map_fd, &next_key, &v) == 0) {
      char ip[INET_ADDRSTRLEN];
      ipv4_to_str(next_key, ip, sizeof(ip));
      printf("%-15s  %-14llu %-13" PRIu32 " %-11" PRIu32 "\n",
             ip,
             (unsigned long long)v.timestamp_sec,
             v.total_packet_count,
             v.total_packet_size);
    }
    key = next_key;
    has_prev = 1;
  }

  if (!has_prev) {
    puts("(empty)");
  }
}

static void dump_ban_map(int map_fd, __u64 now_sec)
{
  __u32 key;
  __u32 next_key;
  int has_prev = 0;

  puts("\n=== ip_ban_list ===");
  puts("source_ip        ban_until_sec    remaining_sec");

  while (bpf_map_get_next_key(map_fd, has_prev ? &key : NULL, &next_key) == 0) {
    struct ban_entry_user v = {0};
    if (bpf_map_lookup_elem(map_fd, &next_key, &v) == 0) {
      char ip[INET_ADDRSTRLEN];
      __u64 remaining = (v.ban_until_sec > now_sec) ? (v.ban_until_sec - now_sec) : 0;
      ipv4_to_str(next_key, ip, sizeof(ip));
      printf("%-15s  %-13llu %-13llu\n",
             ip,
             (unsigned long long)v.ban_until_sec,
             (unsigned long long)remaining);
    }
    key = next_key;
    has_prev = 1;
  }

  if (!has_prev) {
    puts("(empty)");
  }
}

int main(int argc, char **argv)
{
  const char *history_map_path = (argc > 1) ? argv[1] : DEFAULT_HISTORY_MAP_PATH;
  const char *ban_map_path = (argc > 2) ? argv[2] : DEFAULT_BAN_MAP_PATH;

  int history_fd = open_map_or_print(history_map_path);
  if (history_fd < 0) {
    return 1;
  }

  int ban_fd = open_map_or_print(ban_map_path);
  if (ban_fd < 0) {
    close(history_fd);
    return 1;
  }

  __u64 now_sec = (__u64)time(NULL);
  dump_packet_history_map(history_fd);
  dump_ban_map(ban_fd, now_sec);

  close(history_fd);
  close(ban_fd);
  return 0;
}
