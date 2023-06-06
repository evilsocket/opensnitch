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

// even though we only need 32 bits of pid, on x86_32 ebpf verifier complained when pid type was set to u32
typedef u64 pid_size_t;
typedef u64 uid_size_t; 


//-------------------------------map definitions 
// which github.com/iovisor/gobpf/elf expects
typedef struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int pinning;
	char namespace[BUF_SIZE_MAP_NS];
} bpf_map_def;

enum bpf_pin_type {
	PIN_NONE = 0,
	PIN_OBJECT_NS,
	PIN_GLOBAL_NS,
	PIN_CUSTOM_NS,
};
//-----------------------------------

#endif

