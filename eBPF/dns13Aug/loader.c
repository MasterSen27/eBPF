#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>        // ✅ for if_nametoindex()
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h> // ✅ for XDP flags

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    int ifindex;
    int err;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <iface> <bpf_prog.o>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    obj = bpf_object__open_file(argv[2], NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file: %s\n", strerror(errno));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(errno));
        return 1;
    }

    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "Error: No program found in object\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);

    // Attach in SKB (generic) mode
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "Error attaching XDP program: %s\n", strerror(-err));
        return 1;
    }

    printf("XDP program loaded and attached on %s (fd=%d)\n", argv[1], prog_fd);
    printf("Press Enter to detach...\n");
    getchar();

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    printf("XDP program detached\n");

    return 0;
}
