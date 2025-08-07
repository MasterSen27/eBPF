#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>  // Required for uint8_t

#define DNS_PORT 53
#define THRESHOLD_LABEL_LEN 20
#define MAX_TOTAL_LEN 100

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_dns_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void*)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udph = (void *)(iph + 1);
    if ((void*)(udph + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(udph->dest) != DNS_PORT) return XDP_PASS;

    uint8_t *ptr = (uint8_t *)(udph + 1);
    if ((void*)ptr + 12 > data_end) return XDP_PASS; // DNS header is 12 bytes
    ptr += 12;

    int total_len = 0;

    // DNS labels are length-prefixed
    while (ptr < (uint8_t *)data_end) {
        uint8_t len = *ptr;

        if (len == 0) break;

        if (len > THRESHOLD_LABEL_LEN) {
            bpf_printk("Suspicious long label detected: len=%d\n", len);
            return XDP_PASS;
        }

        if (ptr + len + 1 > (uint8_t *)data_end) break;

        ptr += len + 1;
        total_len += len + 1;

        if (total_len > MAX_TOTAL_LEN) {
            bpf_printk("Excessive DNS label length: total_len=%d\n", total_len);
            break;
        }
    }

    return XDP_PASS;
}
