//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "headers/bpf_helpers.h"

struct ipv4_key {
    __be32 ip;
    __u8 protocol;
};

struct ipv6_key {
    struct in6_addr ip;
    __u8 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8);
    __type(value, __u8);
    __uint(max_entries, 256);
} filtered_protocols SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8);
    __type(value, __u8);
    __uint(max_entries, 256);
} blocked_protocols SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv4_key);
    __type(value, __u64);
    __uint(max_entries, 1024);
} ipv4_counter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv6_key);
    __type(value, __u64);
    __uint(max_entries, 1024);
} ipv6_counter_map SEC(".maps");


SEC("xdp")
int xdp_protocol_filter(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    __u16 h_proto = eth->h_proto;
    if (h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr*)(eth + 1);
        if ((void*)(ip + 1) > data_end) {
            return XDP_PASS;
        }
        __u8 protocol = ip->protocol;
        struct ipv4_key key = {};
        key.ip = ip->saddr;
        key.protocol = protocol;
        if (!bpf_map_lookup_elem(&filtered_protocols, &protocol)) {
            return XDP_DROP;
        }
        if (bpf_map_lookup_elem(&blocked_protocols, &protocol)) {
            return XDP_DROP;
        }
        __u64 *count, init_val = 1;
        count = bpf_map_lookup_elem(&ipv4_counter_map, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            bpf_map_update_elem(&ipv4_counter_map, &key, &init_val, BPF_ANY);
        }
    } else if (h_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (struct ipv6hdr*)(eth + 1);
        if ((void*)(ip6 + 1) > data_end) {
            return XDP_PASS;
        }
        __u8 protocol = ip6->nexthdr;
        struct ipv6_key key = {};
        key.ip = ip6->saddr;
        key.protocol = protocol;
        if (!bpf_map_lookup_elem(&filtered_protocols, &protocol)) {
            return XDP_DROP;
        }
        if (bpf_map_lookup_elem(&blocked_protocols, &protocol)) {
            return XDP_DROP;
        }
        __u64 *count, init_val = 1;
        count = bpf_map_lookup_elem(&ipv6_counter_map, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            bpf_map_update_elem(&ipv6_counter_map, &key, &init_val, BPF_ANY);
        }
    }
    return XDP_PASS;
}
