// exec_counter.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Define a BPF map to count syscalls
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} exec_counter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int count_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 key = 0;
    u64 *val;

    val = bpf_map_lookup_elem(&exec_counter, &key);
    if (val)
        __sync_fetch_and_add(val, 1);  // Atomic increment

    return 0;
}
