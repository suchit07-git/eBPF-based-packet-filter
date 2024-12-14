//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "headers/bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} pkt_count SEC(".maps");

SEC("xdp")
int xdp_ip_packet_counter(struct xdp_md* ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    struct iphdr *ip = (struct iphdr*)(eth + 1);
    if ((void*)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    __u64 *count, init_val = 1;
    count = bpf_map_lookup_elem(&pkt_count, &ip->saddr);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(&pkt_count, &ip->saddr, &init_val, BPF_ANY);
    }
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
