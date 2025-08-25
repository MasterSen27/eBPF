// loader.c (fixed)
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/bpf.h>


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <iface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;

    obj = bpf_object__open_file("xdp_dns_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Get first XDP program in object
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "Failed to find a BPF program\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program FD\n");
        return 1;
    }

    if (bpf_xdp_attach(ifindex, prog_fd, 0, NULL) < 0) {
        fprintf(stderr, "Failed to attach XDP program to %s: %s\n", iface, strerror(errno));
        return 1;
    }

    printf("✅ XDP program loaded on %s\n", iface);
    printf("🔎 To view logs: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

    printf("Press Enter to detach and exit...\n");
    getchar();

    // Unload XDP program
    bpf_xdp_detach(ifindex, 0, NULL);
    return 0;
}
