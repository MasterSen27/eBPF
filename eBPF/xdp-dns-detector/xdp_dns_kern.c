// xdp_dns_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

struct dns_hdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

SEC("xdp")
int xdp_dns_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // L2: Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // L3: IPv4
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < (int)sizeof(*ip) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    // L4: UDP
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 sport = bpf_ntohs(udp->source);
    __u16 dport = bpf_ntohs(udp->dest);

    // DNS is UDP/53 (either direction)
    if (!(sport == 53 || dport == 53))
        return XDP_PASS;

    // L7: DNS header (12 bytes)
    struct dns_hdr *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;

    __u16 ulen   = bpf_ntohs(udp->len);
    __u16 id     = bpf_ntohs(dns->id);
    __u16 flags  = bpf_ntohs(dns->flags);
    __u16 qd     = bpf_ntohs(dns->qdcount);
    __u16 an     = bpf_ntohs(dns->ancount);
    __u16 ns     = bpf_ntohs(dns->nscount);
    __u16 ar     = bpf_ntohs(dns->arcount);

    // Parse flags (RFC 1035)
    __u16 QR     = (flags >> 15) & 0x1;       // 0 = query, 1 = response
    __u16 OPCODE = (flags >> 11) & 0xF;       // 4 bits
    __u16 AA     = (flags >> 10) & 0x1;
    __u16 TC     = (flags >> 9)  & 0x1;
    __u16 RD     = (flags >> 8)  & 0x1;
    __u16 RA     = (flags >> 7)  & 0x1;
    __u16 RCODE  = (flags >> 0)  & 0xF;       // 4 bits

    // Keep each printk <= 3 formatted values for older kernels
    bpf_printk("DNS pkt: sport=%u dport=%u ulen=%u\n", sport, dport, ulen);
    bpf_printk("DNS hdr: id=%u qd=%u an=%u\n", id, qd, an);
    bpf_printk("DNS hdr: ns=%u ar=%u flags=0x%x\n", ns, ar, flags);
    bpf_printk("DNS flg: QR=%u OPC=%u AA=%u\n", QR, OPCODE, AA);
    bpf_printk("DNS flg: TC=%u RD=%u RA=%u\n", TC, RD, RA);
    bpf_printk("DNS flg: RCODE=%u\n", RCODE);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
