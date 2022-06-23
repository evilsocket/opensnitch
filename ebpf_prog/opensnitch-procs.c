#define KBUILD_MODNAME "opensnitch-procs"

//uncomment if building on x86_32
//#define OPENSNITCH_x86_32

#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h> 
#include <bpf/bpf_core_read.h>

#define ARGSIZE  128

#ifndef TASK_COMM_LEN
 #define TASK_COMM_LEN 16
#endif


// even though we only need 32 bits of pid, on x86_32 ebpf verifier complained when pid type was set to u32
typedef u64 pid_size_t;
typedef u64 uid_size_t; 


//-------------------------------map definitions 
// which github.com/iovisor/gobpf/elf expects
#define BUF_SIZE_MAP_NS 256

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

//---------------------------------------------------------------------------//

enum events_type {
    EVENT_NONE = 0,
    EVENT_EXEC,
    EVENT_FORK,
    EVENT_SCHED_EXEC,
    EVENT_SCHED_EXIT
};

struct data_t {
    u64 type;
    u64 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u64 uid;
    char filename[ARGSIZE];
    char comm[TASK_COMM_LEN];
}__attribute__((packed));

struct bpf_map_def SEC("maps/proc-events") events = {
    // Since kernel 4.4
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 32768,
};

static __always_inline void new_event(struct pt_regs *ctx, struct data_t* data)
{
    // initializing variables with __builtin_memset() is required
    // for compatibility with bpf on kernel 4.4
    __builtin_memset(data, 0, sizeof(struct data_t));

    struct task_struct *task={0};
    struct task_struct *parent={0};
    __builtin_memset(&task, 0, sizeof(task));
    __builtin_memset(&parent, 0, sizeof(parent));
    task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    data->pid = bpf_get_current_pid_tgid() >> 32;
    // FIXME: always 0?
#ifndef OPENSNITCH_x86_32
    // on i686 -> invalid read from stack
    bpf_probe_read(&data->ppid, sizeof(data->ppid), &parent->tgid);
#endif
    data->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
};

// https://0xax.gitbooks.io/linux-insides/content/SysCall/linux-syscall-4.html
// bprm_execve REGS_PARM3
// https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1796

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx)
{
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    // TODO: use ringbuffer to allocate the absolute path[4096] + arguments
    // TODO: extract args
    //const char *argv = (const char *)PT_REGS_PARM3(ctx);

    struct data_t data={0};
    new_event(ctx, &data);
    data.type = EVENT_EXEC;
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
 
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(struct data_t));
    return 0;
};

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched_sched_process_exit(struct pt_regs *ctx)
{
    struct data_t data={0};
    __builtin_memset(&data, 0, sizeof(data));
    new_event(ctx, &data);
    data.type = EVENT_SCHED_EXIT;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(struct data_t));

    return 0;
};

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;
