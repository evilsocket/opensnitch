/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Minimal vmlinux.h for OpenSnitch CO-RE eBPF programs.
 * CO-RE resolves field offsets at load time via /sys/kernel/btf/vmlinux.
 *
 * This file is self-contained - no kernel headers needed. BPF constants
 * are included here because the BPF cross-compiler cannot use linux/bpf.h.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* Basic types */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef __u16 __sum16;
typedef __u16 u16;
typedef short unsigned int __kernel_sa_family_t;
typedef __kernel_sa_family_t sa_family_t;
typedef long unsigned int __kernel_ulong_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef int __kernel_pid_t;
typedef __kernel_pid_t pid_t;

#define TASK_COMM_LEN 16

/* BPF map types - from linux/bpf.h */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
    BPF_MAP_TYPE_TASK_STORAGE = 29,
    BPF_MAP_TYPE_BLOOM_FILTER = 30,
};

/* BPF map update flags - from linux/bpf.h */
enum {
    BPF_ANY = 0,
    BPF_NOEXIST = 1,
    BPF_EXIST = 2,
    BPF_F_LOCK = 4,
};

/* Architecture-specific pt_regs - needed by bpf_tracing.h macros */
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    union {
        __u16 cs;
        __u64 csx;
    };
    unsigned long flags;
    unsigned long sp;
    union {
        __u16 ss;
        __u64 ssx;
    };
} __attribute__((preserve_access_index));
#elif defined(__TARGET_ARCH_i386)
struct pt_regs {
    unsigned long bx;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long bp;
    unsigned long ax;
    unsigned short ds;
    unsigned short __dsh;
    unsigned short es;
    unsigned short __esh;
    unsigned short fs;
    unsigned short __fsh;
    unsigned short gs;
    unsigned short __gsh;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned short cs;
    unsigned short __csh;
    unsigned long flags;
    unsigned long sp;
    unsigned short ss;
    unsigned short __ssh;
} __attribute__((preserve_access_index));
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
} __attribute__((preserve_access_index));
struct pt_regs {
    union {
        struct user_pt_regs user_regs;
        struct {
            __u64 regs[31];
            __u64 sp;
            __u64 pc;
            __u64 pstate;
        };
    };
    __u64 orig_x0;
    __s32 syscallno;
    __u32 pmr;
} __attribute__((preserve_access_index));
#elif defined(__TARGET_ARCH_arm)
struct pt_regs {
    unsigned long uregs[18];
} __attribute__((preserve_access_index));
#elif defined(__TARGET_ARCH_riscv)
struct pt_regs {
    unsigned long epc;
    unsigned long ra;
    unsigned long sp;
    unsigned long gp;
    unsigned long tp;
    unsigned long t0;
    unsigned long t1;
    unsigned long t2;
    unsigned long s0;
    unsigned long s1;
    unsigned long a0;
    unsigned long a1;
    unsigned long a2;
    unsigned long a3;
    unsigned long a4;
    unsigned long a5;
    unsigned long a6;
    unsigned long a7;
    unsigned long s2;
    unsigned long s3;
    unsigned long s4;
    unsigned long s5;
    unsigned long s6;
    unsigned long s7;
    unsigned long s8;
    unsigned long s9;
    unsigned long s10;
    unsigned long s11;
    unsigned long t3;
    unsigned long t4;
    unsigned long t5;
    unsigned long t6;
    unsigned long status;
    unsigned long badaddr;
    unsigned long cause;
    unsigned long orig_a0;
} __attribute__((preserve_access_index));
#elif defined(__TARGET_ARCH_s390)
typedef struct {
    unsigned long mask;
    unsigned long addr;
} __attribute__((aligned(8))) psw_t;
struct user_pt_regs {
    unsigned long args[1];
    psw_t psw;
    unsigned long gprs[16];
} __attribute__((preserve_access_index));
struct pt_regs {
    union {
        struct user_pt_regs user_regs;
        struct {
            unsigned long args[1];
            psw_t psw;
            unsigned long gprs[16];
        };
    };
    unsigned long orig_gpr2;
    union {
        struct {
            unsigned int int_code;
            unsigned int int_parm;
            unsigned long int_parm_long;
        };
    };
    unsigned long flags;
    unsigned long last_break;
} __attribute__((preserve_access_index));
#elif defined(__TARGET_ARCH_loongarch)
struct pt_regs {
    unsigned long regs[32];
    unsigned long orig_a0;
    unsigned long csr_era;
    unsigned long csr_badvaddr;
    unsigned long csr_crmd;
    unsigned long csr_prmd;
    unsigned long csr_euen;
    unsigned long csr_ecfg;
    unsigned long csr_estat;
} __attribute__((preserve_access_index)) __attribute__((aligned(8)));
#else
#error "Unsupported architecture - add pt_regs definition"
#endif

/* Kernel structs - only fields accessed via BPF_CORE_READ */
struct task_struct {
    struct task_struct *real_parent;
    pid_t tgid;
} __attribute__((preserve_access_index));

struct in6_addr {
    union {
        __be32 u6_addr32[4];
    } in6_u;
} __attribute__((preserve_access_index));

struct sock_common {
    __be16 skc_dport;
    __u16 skc_num;
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    short unsigned int skc_family;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
    u16 sk_type;
    u16 sk_protocol;
} __attribute__((preserve_access_index));

struct socket {
    struct sock *sk;
} __attribute__((preserve_access_index));

struct msghdr {
    void *msg_name;
    union {
        void *msg_control;
    };
} __attribute__((preserve_access_index));

/* Control message header - for ancillary data */
struct cmsghdr {
    __kernel_size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
} __attribute__((preserve_access_index));

struct in_addr {
    __be32 s_addr;
} __attribute__((preserve_access_index));

/* Packet info for IPv4 - used to get source address from ancillary data */
struct in_pktinfo {
    int ipi_ifindex;
    struct in_addr ipi_spec_dst;
    struct in_addr ipi_addr;
} __attribute__((preserve_access_index));

/* Packet info for IPv6 - used to get source address from ancillary data */
struct in6_pktinfo {
    struct in6_addr ipi6_addr;
    int ipi6_ifindex;
} __attribute__((preserve_access_index));

/* CMSG_DATA - returns pointer to data after cmsghdr */
#define CMSG_DATA(cmsg) ((void *)((unsigned long)(cmsg) + sizeof(struct cmsghdr)))

struct sockaddr_in {
    __kernel_sa_family_t sin_family;
    __be16 sin_port;
    struct in_addr sin_addr;
} __attribute__((preserve_access_index));

struct sockaddr_in6 {
    short unsigned int sin6_family;
    __be16 sin6_port;
    __be32 sin6_flowinfo;
    struct in6_addr sin6_addr;
} __attribute__((preserve_access_index));

struct sockaddr {
    sa_family_t sa_family;
} __attribute__((preserve_access_index));

struct sk_buff {
    unsigned char *head;
    unsigned char *data;
    __u16 transport_header;
} __attribute__((preserve_access_index));

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
