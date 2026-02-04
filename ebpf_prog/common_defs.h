#ifndef OPENSNITCH_COMMON_DEFS_H
#define OPENSNITCH_COMMON_DEFS_H

/* vmlinux.h provides kernel type/struct definitions for CO-RE */
#include "bpf_headers/vmlinux.h"

/* libbpf headers */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BUF_SIZE_MAP_NS 256
#define MAPSIZE 12000

/* Network constants - vmlinux.h does not define these */
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

/* Network byte order macros */
#ifndef htonll
#define htonll(x) __builtin_bswap64(x)
#endif

#ifndef htons
#define htons(x) __builtin_bswap16(x)
#endif

#ifndef ntohs
#define ntohs(x) __builtin_bswap16(x)
#endif

#define debug(fmt, ...) \
    ( \
     { \
     char __fmt[] = fmt; \
     bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
     })

/* Type aliases for kernel-style types */
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

/* size_t is arch-dependent - not provided by vmlinux.h */
#if defined(__TARGET_ARCH_i386) || defined(__TARGET_ARCH_arm)
typedef __u32 size_t;
#else
typedef __u64 size_t;
#endif

// even though we only need 32 bits of pid, on x86_32 ebpf verifier complained when pid type was set to u32
typedef u64 pid_size_t;
typedef u64 uid_size_t;

enum bpf_pin_type {
    PIN_NONE = 0,
    PIN_OBJECT_NS,
    PIN_GLOBAL_NS,
    PIN_CUSTOM_NS,
};

#endif

