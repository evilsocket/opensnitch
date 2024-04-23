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
    EVENT_TCP_CONN_DESTROYED,
    EVENT_UDP_CONN_DESTROYED,
    EVENT_RECV_BYTES,
    EVENT_SEND_BYTES
};

struct trace_ev_common {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
};

struct trace_tcp_destroy_sock {
    struct trace_ev_common ext;

    const void * skaddr;
    u16 sport;
    u16 dport;
    u16 family;
    u8 saddr[4];
    u8 daddr[4];
    u8 saddr_v6[16];
    u8 daddr_v6[16];
    u64 cookie;
};

struct trace_sys_enter_execve {
    struct trace_ev_common ext;

    int __syscall_nr;
    char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct trace_sys_enter_execveat {
    struct trace_ev_common ext;

    int __syscall_nr;
    char *filename;
    const char *const *argv;
    const char *const *envp;
    int flags;
};

struct trace_sys_exit_execve {
    struct trace_ev_common ext;

    int __syscall_nr;
    long ret;
};


struct data_t {
    u64 type;
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 uid;
    // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 ppid;
    u32 ret_code;
    u8 args_count;
    u8 args_partial;
    char filename[MAX_PATH_LEN];
    char args[MAX_ARGS][MAX_ARG_SIZE];
    char comm[TASK_COMM_LEN];
    u16 pad1;
    u32 pad2;
};

struct network_event_t {
    u64 type;
    u64 saddr_v6;
    u64 daddr_v6;
    u64 cookie;
    u64 bytes_sent;
    u64 bytes_recv;
    u64 last_sent;
    u32 pid;
    u32 uid;
    u32 ppid;
    u32 proto;

    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 family;
};

//-----------------------------------------------------------------------------
// maps

struct bpf_map_def SEC("maps/heapstore") heapstore = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct data_t),
    .max_entries = 1
};

struct bpf_map_def SEC("maps/tcpBytesMap") tcpBytesMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct network_event_t),
    .max_entries = 13000,
};

struct bpf_map_def SEC("maps/udpBytesMap") udpBytesMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct network_event_t),
    .max_entries = 13001,
};



#endif
