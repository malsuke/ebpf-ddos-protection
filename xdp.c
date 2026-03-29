#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define PACKET_COUNT_THRESHOLD 1000U
#define PACKET_SIZE_THRESHOLD (1024U * 1024U)
#define BAN_TTL_SEC 60U

/**
 * 1秒あたりのパケット数、ウィンドウのリセット時間、最大/最小パケットサイズ、疑わしいパケットサイズのしきい値などの定数を定義
 * 通信の履歴をMapで管理する。（タイムスタンプをつける？）
 * パケットを受信するたびに、送信元IPアドレスをキーとしてMapからレート制限情報を取得
 * 加算方式で
 * 総和
 */

struct packet_history
{
  struct bpf_spin_lock lock;
  __u64 timestamp_sec;
  __u32 total_packet_count;
  __u32 total_packet_size;
};

struct ban_entry
{
  __u64 ban_until_sec;
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct packet_history);
  __uint(max_entries, 65535);
} packet_history_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32);
  __type(value, struct ban_entry);
  __uint(max_entries, 65535);
} ip_ban_list SEC(".maps");

static __always_inline __u64 get_now_sec(void)
{
  return bpf_ktime_get_ns() / 1000000000ULL;
}

static __always_inline int check_rate_limit(__u32 packet_count, __u32 packet_size)
{
  return packet_count > PACKET_COUNT_THRESHOLD || packet_size > PACKET_SIZE_THRESHOLD;
}

SEC("xdp")
int xdp_ddos_protection(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return XDP_PASS;

  if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) return XDP_PASS;

  __u64 now_sec = get_now_sec();
  __u32 src_ip = ip->saddr;
  struct ban_entry *ban = bpf_map_lookup_elem(&ip_ban_list, &src_ip);
  if (ban) {
    if (ban->ban_until_sec > now_sec) return XDP_DROP;
    bpf_map_delete_elem(&ip_ban_list, &src_ip);
  }

  __u32 packet_len = (__u32)(data_end - data);
  struct packet_history *history = bpf_map_lookup_elem(&packet_history_map, &src_ip);

  /**
   * エントリがない場合 -> 初期化
   * エントリがあり、時刻が異なる場合 -> タイムスタンプ更新 & リセット
   * エントリがあり、時刻が同じ場合 -> カウント加算
   * レート制限超過 -> Ban & XDP_DROP
   */
  if (!history) {
    struct packet_history new_history = {
        .timestamp_sec = now_sec,
        .total_packet_count = 1,
        .total_packet_size = packet_len,
    };
    bpf_map_update_elem(&packet_history_map, &src_ip, &new_history, BPF_ANY);
    return XDP_PASS;
  }
  bpf_spin_lock(&history->lock);

  if (history->timestamp_sec != now_sec) {
    history->timestamp_sec = now_sec;
    history->total_packet_count = 1;
    history->total_packet_size = packet_len;
    bpf_spin_unlock(&history->lock);
    return XDP_PASS;
  }

  history->total_packet_count++;
  history->total_packet_size += packet_len;

  int over_limit = check_rate_limit(history->total_packet_count, history->total_packet_size);
  bpf_spin_unlock(&history->lock);

  if (over_limit) {
    struct ban_entry new_ban = {
        .ban_until_sec = now_sec + BAN_TTL_SEC,
    };
    bpf_map_update_elem(&ip_ban_list, &src_ip, &new_ban, BPF_ANY);
    return XDP_DROP;
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
