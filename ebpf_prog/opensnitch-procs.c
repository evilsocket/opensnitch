#define KBUILD_MODNAME "opensnitch-procs"

#include "common.h"

struct bpf_map_def SEC("maps/proc-events") events = {
    // Since kernel 4.4
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 256, // max cpus
};

struct bpf_map_def SEC("maps/execMap") execMap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct data_t),
	.max_entries = 256,
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

#if !defined(__arm__) && !defined(__i386__)
    // on i686 -> invalid read from stack
    bpf_probe_read(&data->ppid, sizeof(u32), &parent->tgid);
#endif
    data->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
};

/*
 * send to userspace the result of the execve* call.
 */
static __always_inline void __handle_exit_execve(struct trace_sys_exit_execve *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct data_t *proc = bpf_map_lookup_elem(&execMap, &pid_tgid);
    if (proc == NULL) { return; }
    if (ctx->ret != 0) { goto out; }
    proc->ret_code = ctx->ret;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, proc, sizeof(*proc));

out:
    bpf_map_delete_elem(&execMap, &pid_tgid);
}

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

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&execMap, &pid_tgid);
    return 0;
};

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls_sys_exit_execve(struct trace_sys_exit_execve *ctx)
{
    __handle_exit_execve(ctx);
    return 0;
};

SEC("tracepoint/syscalls/sys_exit_execveat")
int tracepoint__syscalls_sys_exit_execveat(struct trace_sys_exit_execve *ctx)
{
    __handle_exit_execve(ctx);
    return 0;
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
    // bpf_probe_read_user* helpers were introduced in kernel 5.5
    // Since the args can be overwritten anyway, maybe we could get them from
    // mm_struct instead for a wider kernel version support range?
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), (const char *)ctx->filename);

    const char *argp={0};
    data->args_count = 0;
    data->args_partial = INCOMPLETE_ARGS;

// FIXME: on i386 arch, the following code fails with permission denied.
#if !defined(__arm__) && !defined(__i386__)
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]);
        if (!argp){ data->args_partial = COMPLETE_ARGS; break; }

        if (bpf_probe_read_user_str(&data->args[i], MAX_ARG_SIZE, argp) >= MAX_ARG_SIZE){
            break;
        }
        data->args_count++;
    }
#endif

// FIXME: on aarch64 we fail to save the event to execMap, so send it to userspace here.
#if defined(__aarch64__)
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
#else
    // in case of failure adding the item to the map, send it directly
    u64 pid_tgid = bpf_get_current_pid_tgid();
	if (bpf_map_update_elem(&execMap, &pid_tgid, data, BPF_ANY) != 0) {

        // With some commands, this helper fails with error -28 (ENOSPC). Misleading error? cmd failed maybe?
        // BUG: after coming back from suspend state, this helper fails with error -95 (EOPNOTSUPP)
        // Possible workaround: count -95 errors, and from userspace reinitialize the streamer if errors >= n-errors
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    }
#endif

    return 0;
};

SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint__syscalls_sys_enter_execveat(struct trace_sys_enter_execveat* ctx)
{
    int zero = 0;
    struct data_t *data = {0};
    data = (struct data_t *)bpf_map_lookup_elem(&heapstore, &zero);
    if (!data){ return 0; }

    new_event((void *)data);
    data->type = EVENT_EXECVEAT;
    // bpf_probe_read_user* helpers were introduced in kernel 5.5
    // Since the args can be overwritten anyway, maybe we could get them from
    // mm_struct instead for a wider kernel version support range?
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), (const char *)ctx->filename);

    const char *argp={0};
    data->args_count = 0;
    data->args_partial = INCOMPLETE_ARGS;

// FIXME: on i386 arch, the following code fails with permission denied.
#if !defined(__arm__) && !defined(__i386__)
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]);
        if (!argp){ data->args_partial = COMPLETE_ARGS; break; }

        if (bpf_probe_read_user_str(&data->args[i], MAX_ARG_SIZE, argp) >= MAX_ARG_SIZE){
            break;
        }
        data->args_count++;
    }
#endif

// FIXME: on aarch64 we fail to save the event to execMap, so send it to userspace here.
#if defined(__aarch64__)
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
#else
    // in case of failure adding the item to the map, send it directly
    u64 pid_tgid = bpf_get_current_pid_tgid();
	if (bpf_map_update_elem(&execMap, &pid_tgid, data, BPF_ANY) != 0) {

        // With some commands, this helper fails with error -28 (ENOSPC). Misleading error? cmd failed maybe?
        // BUG: after coming back from suspend state, this helper fails with error -95 (EOPNOTSUPP)
        // Possible workaround: count -95 errors, and from userspace reinitialize the streamer if errors >= n-errors
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    }
#endif

    return 0;
};



char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;
