// xdp_dns_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>           // IPPROTO_UDP
#include <bpf/bpf_endian.h>     // bpf_ntohs()

SEC("xdp")
int xdp_dns_filter(struct xdp_md *ctx) {
    // Debug print to confirm packet hit
    bpf_printk("Packet received\n");

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // Detect DNS (UDP port 53)
    __u16 dport = bpf_ntohs(udp->dest);
    __u16 sport = bpf_ntohs(udp->source);

    if (dport == 53 || sport == 53) {
      bpf_printk("DNS matched! sport=%d, dport=%d, len=%d\n", sport, dport, bpf_ntohs(udp->len));
    }


    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

