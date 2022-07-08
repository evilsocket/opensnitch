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

static __always_inline void new_event(struct data_t* data)
{
    // initializing variables with __builtin_memset() is required
    // for compatibility with bpf on kernel 4.4

    struct task_struct *task;
    struct task_struct *parent;
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

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched_sched_process_exit(struct pt_regs *ctx)
{
    int zero = 0;
    struct data_t *data = bpf_map_lookup_elem(&heapstore, &zero);
    if (!data){ return 0; }

    new_event(data);
    data->type = EVENT_SCHED_EXIT;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));

    return 0;
};

struct trace_sys_enter_execve {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls_sys_enter_execve(struct trace_sys_enter_execve* ctx)
{
	int zero = 0;
	struct data_t *data = {0};
    data = (struct data_t *)bpf_map_lookup_elem(&heapstore, &zero);
	if (!data){ return 0; }

	new_event(data);
	data->type = EVENT_EXEC;
	bpf_probe_read_user_str(&data->filename, sizeof(data->filename), (const char *)ctx->filename);

	/* if we get the args, we'd have to be sure that we get the whole cmdline,
	 * either by allocating the whole cmdline, or by sending each arg to userspace.
    const char *argp={0};
    data->args_count = 0;
    #pragma unroll (full)
	for (int i = 0; i < MAX_ARGS; i++) {
	  bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]);
	  if (!argp){ break; }

	  bpf_probe_read_user_str(&data->args[i], MAX_ARG_SIZE, argp);
      data->args_count++;
	}*/

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
	return 0;
};

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;
