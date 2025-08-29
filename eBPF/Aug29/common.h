// common.h - shared between BPF and user space

#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

// Event struct sent through ringbuf
struct dns_event {
    __u32 saddr, daddr;
    __u16 sport, dport;
    __u16 qtype;
    __u16 sublen;
    char domain_name[256]; // Add domain name field
};

#endif /* __COMMON_H */
