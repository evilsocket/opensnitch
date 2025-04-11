#ifndef OPENSNITCH_COMMON_DEFS_H
#define OPENSNITCH_COMMON_DEFS_H

#include <linux/sched.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include "bpf_headers/bpf_helpers.h"
#include "bpf_headers/bpf_tracing.h"
//#include <bpf/bpf_core_read.h> 

#define BUF_SIZE_MAP_NS 256
#define MAPSIZE 12000

#define debug(fmt, ...) \
    ( \
     { \
     char __fmt[] = fmt; \
     bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
     })

// even though we only need 32 bits of pid, on x86_32 ebpf verifier complained when pid type was set to u32
typedef u64 pid_size_t;
typedef u64 uid_size_t; 

enum bpf_pin_type {
    PIN_NONE = 0,
    PIN_OBJECT_NS,
    PIN_GLOBAL_NS,
    PIN_CUSTOM_NS,
};
//-----------------------------------

#endif

