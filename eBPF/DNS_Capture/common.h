#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

struct dns_event {
    __u64 timestamp;    // Timestamp in nanoseconds
    __u32 saddr;        // Source IP address
    __u32 daddr;        // Destination IP address
    __u16 sport;        // Source port
    __u16 dport;        // Destination port
    __u16 qtype;        // Query type
    __u8  rcode;        // Response code
    __u16 sublen;       // Subdomain length
    char domain_name[256]; // Domain name
};

#endif /* __COMMON_H */
