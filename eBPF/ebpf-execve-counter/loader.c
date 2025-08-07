// loader.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int map_fd;

// Signal handler: Print count and exit
void print_count(int signo) {
    __u32 key = 0;
    __u64 value = 0;

    if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
        printf("\n[+] execve calls: %llu\n", value);
    } else {
        perror("bpf_map_lookup_elem");
    }

    exit(0);
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;

    signal(SIGINT, print_count);  // Handle Ctrl+C

    // Load BPF object file
    obj = bpf_object__open_file("exec_counter.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Find program and map
    prog = bpf_object__find_program_by_name(obj, "count_execve");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "exec_counter");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find BPF map\n");
        return 1;
    }

    // Attach to tracepoint
    link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve");
    if (!link) {
        fprintf(stderr, "Failed to attach tracepoint\n");
        return 1;
    }

    printf("Running... Press Ctrl+C to stop and show execve count.\n");

    // Idle loop
    while (1) pause();

    bpf_link__destroy(link);
    return 0;
}
