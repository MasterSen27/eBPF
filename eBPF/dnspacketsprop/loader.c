#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <net/if.h>
#include <bpf/libbpf.h>

#include "xdp_dns_kern.skel.h"
#include "common.h"   // <-- bring in struct dns_event

static volatile bool exiting = false;

static void sig_handler(int signo)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct dns_event *e = data;

    printf("DNS Packet: src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u "
           "qtype=%u sublen=%u\n",
           (e->saddr >> 24) & 0xff, (e->saddr >> 16) & 0xff,
           (e->saddr >> 8) & 0xff,  e->saddr & 0xff, e->sport,
           (e->daddr >> 24) & 0xff, (e->daddr >> 16) & 0xff,
           (e->daddr >> 8) & 0xff,  e->daddr & 0xff, e->dport,
           e->qtype, e->sublen);

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct xdp_dns_kern *skel;   // <-- fixed type
    struct bpf_link *link = NULL;
    int ifindex;
    int err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "Invalid ifname %s\n", argv[1]);
        return 1;
    }

    // Load skeleton
    skel = xdp_dns_kern__open_and_load();  // <-- fixed
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF object\n");
        return 1;
    }

    // Attach XDP program
    link = bpf_program__attach_xdp(skel->progs.xdp_dns_filter, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        xdp_dns_kern__destroy(skel);
        return 1;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_link__destroy(link);
        xdp_dns_kern__destroy(skel);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Running... press Ctrl+C to exit\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    xdp_dns_kern__destroy(skel);

    return 0;
}
