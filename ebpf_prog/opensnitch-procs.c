#define KBUILD_MODNAME "opensnitch-procs"

#include "common.h"
#include <net/sock.h>

struct {
    // Since kernel 5.8
    __uint(type, BPF_MAP_TYPE_RINGBUF);

    // max_entries must be:
    // - no 0
    // - multiple of 4096
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct data_t);
    __uint(max_entries, 1024);
} execMap SEC(".maps");

static __always_inline void new_event(struct data_t* data)
{
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
    struct data_t *proc = (struct data_t *)bpf_map_lookup_elem(&execMap, &pid_tgid);
    // don't delete the pid from execMap here, delegate it to sched_process_exit
    if (proc == NULL) { return; }
    if (ctx->ret != 0) {
        debug("exec EXIT: ret != 0: %d, pid: %d -> %s\n", ctx->ret, pid_tgid, proc->filename);
        //return;
    }
    proc->ret_code = ctx->ret;

    int ret = bpf_ringbuf_output(&events, proc, sizeof(*proc), 0);
    if (ret != 0){
        debug("execve send error: %d, %d, %s\n", ret, pid_tgid, proc->filename);
    }
}

// https://0xax.gitbooks.io/linux-insides/content/SysCall/linux-syscall-4.html
// bprm_execve REGS_PARM3
// https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1796

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched_sched_process_exit(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct data_t *proc = (struct data_t *)bpf_map_lookup_elem(&execMap, &pid_tgid);
    // if the pid is not in execMap cache (because it's not of a pid we've
    // previously intercepted), do not send the event to userspace, because
    // we won't do anything with it and it consumes CPU cycles (too much in some
    // scenarios).
    if (proc == NULL) { return 0; }

    int zero = 0;
    struct data_t *data = (struct data_t *)bpf_map_lookup_elem(&heapstore, &zero);
    if (!data){ return 0; }

    new_event(data);
    data->type = EVENT_SCHED_EXIT;
    bpf_ringbuf_output(&events, data, sizeof(*data), 0);

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
    struct data_t *data = (struct data_t *)bpf_map_lookup_elem(&heapstore, &zero);
    if (!data){
        debug("sys_enter_execve: error reserving data space\n");
        return 0;
    }
    new_event(data);
    data->type = EVENT_EXEC;
    // bpf_probe_read_user* helpers were introduced in kernel 5.5
    // Since the args can be overwritten anyway, maybe we could get them from
    // mm_struct instead for a wider kernel version support range?
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), (const char *)ctx->filename);

// FIXME: on i386 arch, the following code fails with permission denied.
#if !defined(__arm__) && !defined(__i386__)
    const char *argp={0};
    data->args_count = 0;
    data->args_partial = INCOMPLETE_ARGS;

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
    bpf_ringbuf_output(&events, data, sizeof(*data), 0);
#else
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // in case of failure adding the item to the map, send it directly
    if (bpf_map_update_elem(&execMap, &pid_tgid, data, BPF_ANY) != 0) {

        // https://docs.ebpf.io/linux/helper-function/bpf_perf_event_output/
        //
        // "Each perf event is created on a specific CPU. This helper can only
        // write to perf events on the same CPU as the eBPF program is running.
        // Manually picking an index containing a perf event on a different CPU
        // will result in a -EOPNOTSUPP error at runtime. So unless there is a
        // good reason to do so, its recommended to use BPF_F_CURRENT_CPU and to
        // populate the BPF_MAP_TYPE_PERF_EVENT_ARRAY map in such a way where the
        // CPU indices and map indices are the same."
        //
        // -95 EOPNOTSUPP (op not supported) -> event on different CPU.
        //     https://elixir.bootlin.com/linux/v5.2.21/source/kernel/trace/bpf_trace.c#L413
        // -28 ENOSPC (no space left)
        //     -> perf reader buffer too small.
        //     -> also happens after coming back from suspend state.
        // -7 E2BIG (arg list too long) -> too much args?
        // -2 ENOENT (no such file or directory) -> map index not found. on different cpu?

        bpf_ringbuf_output(&events, data, sizeof(*data), 0);
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
    if (!data){
        debug("sys_enter_execveat: error reserving data space\n");
        return 0;
    }

    new_event((void *)data);
    data->type = EVENT_EXECVEAT;
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), (const char *)ctx->filename);

// FIXME: on i386 arch, the following code fails with permission denied.
#if !defined(__arm__) && !defined(__i386__)
    const char *argp={0};
    data->args_count = 0;
    data->args_partial = INCOMPLETE_ARGS;

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

#if defined(__aarch64__)
    bpf_ringbuf_output(&events, data, sizeof(*data), 0);
#else
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&execMap, &pid_tgid, data, BPF_ANY) != 0) {

        bpf_ringbuf_output(&events, data, sizeof(*data), 0);
    }
#endif

    return 0;
};

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;
