#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#include "xdp_dns_kern.skel.h"
#include "common.h"

static volatile bool exiting = false;

static void sig_handler(int signo)
{
    exiting = true;
}

static const char *rcode_to_str(__u8 rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        default: return "UNKNOWN";
    }
}

static double calculate_shannon_entropy(const char *data, size_t len) {
    if (len == 0) return 0.0;
    
    int frequency[256] = {0};
    double entropy = 0.0;
    
    // Calculate byte frequencies
    for (size_t i = 0; i < len; i++) {
        frequency[(unsigned char)data[i]]++;
    }
    
    // Calculate entropy
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double probability = (double)frequency[i] / len;
            entropy -= probability * log2(probability);
        }
    }
    
    return entropy;
}

static int set_boot_time_offset(struct xdp_dns_kern *skel)
{
    struct timespec boot_time, current_time;
    __u64 boot_time_ns, current_time_ns, offset;
    __u32 key = 0;
    int map_fd, err;
    
    // Get current time
    clock_gettime(CLOCK_REALTIME, &current_time);
    current_time_ns = current_time.tv_sec * 1000000000ULL + current_time.tv_nsec;
    
    // Get boot time (monotonic clock base)
    clock_gettime(CLOCK_BOOTTIME, &boot_time);
    boot_time_ns = boot_time.tv_sec * 1000000000ULL + boot_time.tv_nsec;
    
    // Calculate offset: wall_clock = boot_time_offset + monotonic_time
    offset = current_time_ns - boot_time_ns;
    
    // Get map file descriptor and update the BPF map
    map_fd = bpf_map__fd(skel->maps.boot_time_offset);
    err = bpf_map_update_elem(map_fd, &key, &offset, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to set boot time offset: %s\n", strerror(-err));
        return err;
    }
    
    printf("Boot time offset set: %llu ns\n", offset);
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct dns_event *e = data;
    
    // Calculate Shannon entropy from raw domain
    double entropy = calculate_shannon_entropy(e->raw_domain, e->sublen);
    
    // Convert timestamp to human-readable format
    struct tm *tm_info;
    char timestamp_buf[20];
    time_t seconds = e->timestamp / 1000000000;
    long nanoseconds = e->timestamp % 1000000000;
    tm_info = localtime(&seconds);
    strftime(timestamp_buf, sizeof(timestamp_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("DNS Packet: time=%s.%09ld src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u "
           "qtype=%u rcode=%s(%u) sublen=%u domain=%s entropy=%.3f\n",
           timestamp_buf, nanoseconds,
           (e->saddr >> 24) & 0xff, (e->saddr >> 16) & 0xff,
           (e->saddr >> 8) & 0xff,  e->saddr & 0xff, e->sport,
           (e->daddr >> 24) & 0xff, (e->daddr >> 16) & 0xff,
           (e->daddr >> 8) & 0xff,  e->daddr & 0xff, e->dport,
           e->qtype, rcode_to_str(e->rcode), e->rcode, 
           e->sublen, e->domain_name, entropy);

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct xdp_dns_kern *skel;
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
    skel = xdp_dns_kern__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF object\n");
        return 1;
    }

    // Set boot time offset for correct timestamp calculation
    err = set_boot_time_offset(skel);
    if (err) {
        fprintf(stderr, "Warning: Could not set boot time offset, timestamps will be relative to boot\n");
    }

    // Attach XDP program
    link = bpf_program__attach_xdp(skel->progs.xdp_dns_filter, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        xdp_dns_kern__destroy(skel);
        return 1;
    }

    // Pin the maps so monitor can access them
    err = bpf_map__pin(skel->maps.query_rate_min, "/sys/fs/bpf/query_rate_min");
    if (err) {
        fprintf(stderr, "Failed to pin query_rate_min map: %s\n", strerror(-err));
    }
    
    err = bpf_map__pin(skel->maps.total_q_min, "/sys/fs/bpf/total_q_min");
    if (err) {
        fprintf(stderr, "Failed to pin total_q_min map: %s\n", strerror(-err));
    }
    
    err = bpf_map__pin(skel->maps.query_by_type, "/sys/fs/bpf/query_by_type");
    if (err) {
        fprintf(stderr, "Failed to pin query_by_type map: %s\n", strerror(-err));
    }
    
    err = bpf_map__pin(skel->maps.boot_time_offset, "/sys/fs/bpf/boot_time_offset");
    if (err) {
        fprintf(stderr, "Failed to pin boot_time_offset map: %s\n", strerror(-err));
    }
    
    printf("Maps pinned to /sys/fs/bpf/\n");

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Running... press Ctrl+C to exit\n");
    printf("DNS events will be displayed here with Shannon entropy values.\n");
    printf("Run './monitor.sh' in another terminal for statistics.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    // Unpin maps on exit
    bpf_map__unpin(skel->maps.query_rate_min, "/sys/fs/bpf/query_rate_min");
    bpf_map__unpin(skel->maps.total_q_min, "/sys/fs/bpf/total_q_min");
    bpf_map__unpin(skel->maps.query_by_type, "/sys/fs/bpf/query_by_type");
    bpf_map__unpin(skel->maps.boot_time_offset, "/sys/fs/bpf/boot_time_offset");
    
    ring_buffer__free(rb);
    if (link) {
        bpf_link__destroy(link);
    }
    xdp_dns_kern__destroy(skel);

    return 0;
}
