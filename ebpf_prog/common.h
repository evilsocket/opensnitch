#ifndef OPENSNITCH_COMMON_H
#define OPENSNITCH_COMMON_H

#include "common_defs.h"

//https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/limits.h#L13
#ifndef MAX_PATH_LEN
 #define MAX_PATH_LEN  4096
#endif

//https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/binfmts.h#L16
#define MAX_CMDLINE_LEN 4096
// max args that I've been able to use before hitting the error:
// "dereference of modified ctx ptr disallowed"
#define MAX_ARGS 20
#define MAX_ARG_SIZE 256

// flags to indicate if we were able to read all the cmdline arguments,
// or if one of the arguments is >= MAX_ARG_SIZE, or there more than MAX_ARGS
#define COMPLETE_ARGS 0
#define INCOMPLETE_ARGS 1

#ifndef TASK_COMM_LEN
 #define TASK_COMM_LEN 16
#endif

#define BUF_SIZE_MAP_NS 256
#define GLOBAL_MAP_NS "256"
enum events_type {
    EVENT_NONE = 0,
    EVENT_EXEC,
    EVENT_EXECVEAT,
    EVENT_FORK,
    EVENT_SCHED_EXIT,
};


struct data_t {
    u64 type;
    u64 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u64 uid;
    u64 args_count;
    u64 args_partial;
    char filename[MAX_PATH_LEN];
    char args[MAX_ARGS][MAX_ARG_SIZE];
    char comm[TASK_COMM_LEN];
}__attribute__((packed));

//-----------------------------------------------------------------------------
// maps

struct bpf_map_def SEC("maps/heapstore") heapstore = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct data_t),
	.max_entries = 1
};

#endif
