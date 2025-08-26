// SPDX-License-Identifier: GPL-2.0
#define KBUILD_MODNAME "xdp_dns"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>   // <-- for IPPROTO_UDP etc.

#include "common.h"


#ifndef BPF_MAP_TYPE_RINGBUF   // <-- in case your headers are old
#define BPF_MAP_TYPE_RINGBUF 27
#endif

char __license[] SEC("license") = "GPL";


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB ring buffer
} events SEC(".maps");

struct event {
    __u32 saddr;      // IPv4
    __u32 daddr;      // IPv4
    __u16 sport;      // host byte order
    __u16 dport;      // host byte order
    __u16 qtype;      // host byte order
    __u16 sub_len;    // number of bytes in QNAME (without final 0)
};

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

    // Must have at least one question to parse QNAME/QTYPE
    if (bpf_ntohs(dns->qdcount) == 0)
        return XDP_PASS;

    // QNAME starts just after DNS header
    unsigned char *name = (unsigned char *)(dns + 1);

    // Compute subdomain length safely (bounded & checked)
    // DNS name max length is 255, use a bounded loop for the verifier
    const int MAX_NAME = 255;
    __u16 sub_len = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_NAME; i++) {
        // Ensure we can read name[i]
        if ((void *)(name + i + 1) > data_end) {
            // Truncated; give up
            sub_len = 0;
            break;
        }

        unsigned char c = name[i];
        if (c == 0) {
            sub_len = (__u16)i; // number of bytes before the final 0
            break;
        }
    }

    if (sub_len == 0) {
        // Either empty or truncated name; pass
        return XDP_PASS;
    }

    // After the terminating 0 comes QTYPE (2 bytes) + QCLASS (2 bytes)
    unsigned char *after_name = name + sub_len + 1;

    if ((void *)(after_name + 4) > data_end)
        return XDP_PASS;

    __u16 qtype  = bpf_ntohs(*(__be16 *)(after_name + 0));
    // __u16 qclass = bpf_ntohs(*(__be16 *)(after_name + 2)); // currently unused

    // Send to user space
    struct event ev = {};
    ev.saddr   = bpf_ntohl(ip->saddr);
    ev.daddr   = bpf_ntohl(ip->daddr);
    ev.sport   = sport;
    ev.dport   = dport;
    ev.qtype   = qtype;
    ev.sub_len = sub_len;

    // Output via ring buffer; 0 = BPF_RB_NO_WAKEUP (userspace polls)
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

    return XDP_PASS;
}
