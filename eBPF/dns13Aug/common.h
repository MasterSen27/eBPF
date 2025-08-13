#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

struct dns_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

#endif
