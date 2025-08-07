#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/tcp.h>

struct data_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} telemetry_events SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;

    struct data_t *rec = bpf_ringbuf_reserve(&telemetry_events, sizeof(struct data_t), 0);
    if (!rec) return XDP_PASS;

    rec->src_ip = ip->saddr;
    rec->dst_ip = ip->daddr;
    rec->protocol = ip->protocol;

    // Get port info if TCP/UDP
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        struct tcphdr *tcp = (void*)ip + ip->ihl * 4;
        if ((void*)(tcp + 1) > data_end) {
            bpf_ringbuf_discard(rec, 0);
            return XDP_PASS;
        }
        rec->src_port = tcp->source;
        rec->dst_port = tcp->dest;
    }

    bpf_ringbuf_submit(rec, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
