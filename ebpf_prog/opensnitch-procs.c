#define KBUILD_MODNAME "opensnitch-procs"

//uncomment if building on x86_32
//#define OPENSNITCH_x86_32

#include "common.h"

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
    // TODO: extract args
    //const char *argv = (const char *)PT_REGS_PARM3(ctx);

    int zero = 0;
    struct data_t *data = bpf_map_lookup_elem(&heapstore, &zero);
    if (!data){ return 0; }

    new_event(ctx, data);
    data->type = EVENT_EXEC;
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), filename);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    return 0;
};

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched_sched_process_exit(struct pt_regs *ctx)
{
    int zero = 0;
    struct data_t *data = bpf_map_lookup_elem(&heapstore, &zero);
    if (!data){ return 0; }

    //__builtin_memset(data, 0, sizeof(struct data_t));
    new_event(ctx, data);
    data->type = EVENT_SCHED_EXIT;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    return 0;
};

    return 0;
};

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;
