// SPDX-License-Identifier: GPL-2.0
#define KBUILD_MODNAME "xdp_dns"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include "common.h"

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

char __license[] SEC("license") = "GPL";

// Ring buffer for event streaming
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB ring buffer
} events SEC(".maps");

// Per-CPU array to store event data (avoid large stack usage)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_event);
} event_storage SEC(".maps");

// Per-CPU array for domain parsing (to avoid stack overflow)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2); // Two slots: 0 for domain_name, 1 for raw_domain
    __type(key, __u32);
    __type(value, char[MAX_DOMAIN_LEN]);
} domain_storage SEC(".maps");

// Query rate tracking maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64); // timestamp_minute + domain_hash
    __type(value, __u32); // query count
} query_rate_min SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32); // timestamp_minute
    __type(value, __u32); // total queries
} total_q_min SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u64); // timestamp_minute + qtype
    __type(value, __u32); // query count by type
} query_by_type SEC(".maps");

// Map to store boot time offset
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} boot_time_offset SEC(".maps");

struct dns_hdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

static __always_inline int parse_ipv4_udp(void *data, void *data_end,
                                          struct iphdr **iph,
                                          struct udphdr **udph,
                                          void **l4_payload)
{
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return -1;

    h_proto = eth->h_proto;
    if (h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = data + nh_off;
    if ((void *)(ip + 1) > data_end)
        return -1;
    if (ip->protocol != IPPROTO_UDP)
        return -1;

    __u32 iphdr_len = ip->ihl * 4;
    if (iphdr_len < sizeof(*ip))
        return -1;
    if ((void *)ip + iphdr_len > data_end)
        return -1;

    struct udphdr *udp = (void *)ip + iphdr_len;
    if ((void *)(udp + 1) > data_end)
        return -1;

    *iph = ip;
    *udph = udp;
    *l4_payload = (void *)(udp + 1);
    return 0;
}

static __always_inline __u64 get_wall_clock_time(void)
{
    __u32 key = 0;
    __u64 *boot_time = bpf_map_lookup_elem(&boot_time_offset, &key);
    
    if (boot_time) {
        return *boot_time + bpf_ktime_get_boot_ns();
    }
    
    // Fallback: return boot time if offset not set
    return bpf_ktime_get_boot_ns();
}

static __always_inline void track_query_rate(__u16 qtype, const char *domain_name, __u16 sub_len)
{
    // Get current time in minute granularity
    __u64 timestamp_ns = get_wall_clock_time();
    __u32 timestamp_minute = timestamp_ns / (60 * 1000000000ULL);
    
    // Create hash of domain name for tracking
    __u32 domain_hash = 0;
    for (int i = 0; i < sub_len && i < 64; i++) {
        domain_hash = (domain_hash * 31) + domain_name[i];
    }
    
    // Track per domain per minute
    __u64 domain_key = ((__u64)timestamp_minute << 32) | domain_hash;
    __u32 *domain_count = bpf_map_lookup_elem(&query_rate_min, &domain_key);
    if (domain_count) {
        (*domain_count)++;
    } else {
        __u32 new_count = 1;
        bpf_map_update_elem(&query_rate_min, &domain_key, &new_count, BPF_ANY);
    }
    
    // Track total queries per minute
    __u32 *total_count = bpf_map_lookup_elem(&total_q_min, &timestamp_minute);
    if (total_count) {
        (*total_count)++;
    } else {
        __u32 new_total = 1;
        bpf_map_update_elem(&total_q_min, &timestamp_minute, &new_total, BPF_ANY);
    }
    
    // Track queries by type per minute
    __u64 type_key = ((__u64)timestamp_minute << 16) | qtype;
    __u32 *type_count = bpf_map_lookup_elem(&query_by_type, &type_key);
    if (type_count) {
        (*type_count)++;
    } else {
        __u32 new_type_count = 1;
        bpf_map_update_elem(&query_by_type, &type_key, &new_type_count, BPF_ANY);
    }
}

SEC("xdp")
int xdp_dns_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    struct iphdr *ip;
    struct udphdr *udp;
    void *payload;

    if (parse_ipv4_udp(data, data_end, &ip, &udp, &payload) < 0)
        return XDP_PASS;

    // Only DNS (either src or dst port 53)
    __u16 sport = bpf_ntohs(udp->source);
    __u16 dport = bpf_ntohs(udp->dest);
    if (sport != 53 && dport != 53)
        return XDP_PASS;

    // DNS header present?
    if (payload + sizeof(struct dns_hdr) > data_end)
        return XDP_PASS;

    struct dns_hdr *dns = payload;

    // Extract RCODE from flags (bits 0-3 of the second byte)
    __u8 rcode = (bpf_ntohs(dns->flags) & 0x0F);

    // Must have at least one question to parse QNAME/QTYPE
    if (bpf_ntohs(dns->qdcount) == 0)
        return XDP_PASS;

    // QNAME starts just after DNS header
    unsigned char *name = (unsigned char *)(dns + 1);

    // Compute subdomain length safely (bounded & checked)
    const int MAX_NAME = 255;
    __u16 sub_len = 0;
    
    // Get domain storage from per-CPU array
    __u32 domain_key = 0;
    __u32 raw_key = 1;
    char *domain_name = bpf_map_lookup_elem(&domain_storage, &domain_key);
    char *raw_domain = bpf_map_lookup_elem(&domain_storage, &raw_key);
    
    if (!domain_name || !raw_domain) {
        return XDP_PASS;
    }
    
    // Initialize storage
    domain_name[0] = '\0';
    raw_domain[0] = '\0';
    int domain_pos = 0;
    int raw_pos = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_NAME; i++) {
        if ((void *)(name + i + 1) > data_end) {
            sub_len = 0;
            break;
        }

        unsigned char c = name[i];
        if (c == 0) {
            sub_len = (__u16)i;
            break;
        }
        
        // Store printable domain name characters
        if (domain_pos < MAX_DOMAIN_LEN - 1) {
            domain_name[domain_pos++] = c;
        }
        
        // Store raw domain bytes for entropy calculation
        if (raw_pos < MAX_RAW_DOMAIN_LEN - 1) {
            raw_domain[raw_pos++] = c;
        }
    }
    
    if (domain_pos < MAX_DOMAIN_LEN) {
        domain_name[domain_pos] = '\0';
    }
    
    if (raw_pos < MAX_RAW_DOMAIN_LEN) {
        raw_domain[raw_pos] = '\0';
    }

    if (sub_len == 0) {
        return XDP_PASS;
    }

    // After the terminating 0 comes QTYPE (2 bytes) + QCLASS (2 bytes)
    unsigned char *after_name = name + sub_len + 1;

    if ((void *)(after_name + 4) > data_end)
        return XDP_PASS;

    __u16 qtype  = bpf_ntohs(*(__be16 *)(after_name + 0));

    // Track query rate statistics
    track_query_rate(qtype, domain_name, sub_len);

    // Use per-CPU array to avoid large stack usage
    __u32 event_key = 0;
    struct dns_event *ev = bpf_map_lookup_elem(&event_storage, &event_key);
    if (!ev) {
        return XDP_PASS;
    }

    // Fill event data
    ev->timestamp = get_wall_clock_time();
    ev->saddr     = bpf_ntohl(ip->saddr);
    ev->daddr     = bpf_ntohl(ip->daddr);
    ev->sport     = sport;
    ev->dport     = dport;
    ev->qtype     = qtype;
    ev->rcode     = rcode;
    ev->sublen    = sub_len;
    
    // Copy domain name to event struct
    bpf_probe_read_kernel_str(ev->domain_name, sizeof(ev->domain_name), domain_name);
    bpf_probe_read_kernel_str(ev->raw_domain, sizeof(ev->raw_domain), raw_domain);

    // Output via ring buffer
    bpf_ringbuf_output(&events, ev, sizeof(*ev), 0);

    return XDP_PASS;
}
