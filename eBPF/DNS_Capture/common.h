#ifndef __COMMON_H
#define __COMMON_H

#define MAX_DOMAIN_LEN 255
#define MAX_RAW_DOMAIN_LEN 255

struct dns_event {
    __u64 timestamp;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 qtype;
    __u8 rcode;
    __u16 sublen;
    char domain_name[MAX_DOMAIN_LEN];
    char raw_domain[MAX_RAW_DOMAIN_LEN];
};

#endif /* __COMMON_H */
