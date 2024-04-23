#define KBUILD_MODNAME "opensnitch-procs"

#include "common.h"
#include <net/sock.h>

struct bpf_map_def SEC("maps/proc-events") events = {
    // Since kernel 4.4
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 256, // max cpus
};

struct bpf_map_def SEC("maps/execMap") execMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct data_t),
    .max_entries = 257,
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

static int __always_inline __handle_destroy_sock(struct pt_regs *ctx, short proto, short fam)
{
#if defined(__i386__)
    // On x86_32 platforms accessing arguments using PT_REGS_PARM1 seems to cause probles.
    // That's why we are accessing registers directly.
    struct sock *sk = (struct sock *)((ctx)->ax);
#else
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
#endif
    bpf_probe_read(&fam, sizeof(fam), &sk->__sk_common.skc_family);
    if (fam != AF_INET && fam != AF_INET6){
        return 0;
    }

    struct network_event_t *net_event={0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    // invalid pid / unable to obtain it
    if (pid == 0){
        return 0;
    }

    if (proto == IPPROTO_UDP){
        net_event = (struct network_event_t *)bpf_map_lookup_elem(&udpBytesMap, &pid_tgid);
    } else {
        net_event = (struct network_event_t *)bpf_map_lookup_elem(&tcpBytesMap, &pid_tgid);
    }
    if (!net_event){
        return 0;
    }

    net_event->proto = proto;
    net_event->pid = pid;
    net_event->family = fam;
    bpf_probe_read(&net_event->proto, sizeof(u8), &sk->sk_protocol);
    bpf_probe_read(&net_event->dport, sizeof(net_event->dport), &sk->__sk_common.skc_dport);
    bpf_probe_read(&net_event->sport, sizeof(net_event->sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&net_event->daddr, sizeof(net_event->daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&net_event->saddr, sizeof(net_event->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&net_event->cookie, sizeof(net_event->cookie), &sk->__sk_common.skc_cookie);

    net_event->type = EVENT_TCP_CONN_DESTROYED;
    if (proto == IPPROTO_UDP){
        net_event->type = EVENT_UDP_CONN_DESTROYED;
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, net_event, sizeof(*net_event));
    if (proto == IPPROTO_UDP){
        bpf_map_delete_elem(&udpBytesMap, &pid_tgid);
    } else {
        bpf_map_delete_elem(&tcpBytesMap, &pid_tgid);
    }

    return 0;
};

/**
 * A common function to count bytes per protocol and type (recv/sent).
 * Bytes are only sent to userspace every +-3 seconds, or on the first packet
 * seen, otherwise they're accumulated.
 */
static int __always_inline __handle_transfer_bytes(struct pt_regs *ctx, short proto, short fam, short type)
{
  int slen = PT_REGS_RC(ctx);
  if (slen < 0){
      return 0;
  }

  u64 now = bpf_ktime_get_ns();
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  // TODO: check pid == 0?

  struct network_event_t *net_event=NULL;
  if (proto == IPPROTO_TCP){
      net_event = (struct network_event_t *)bpf_map_lookup_elem(&tcpBytesMap, &pid_tgid);
  }
  else if (proto == IPPROTO_UDP){
      net_event = (struct network_event_t *)bpf_map_lookup_elem(&udpBytesMap, &pid_tgid);
  }

  if (!net_event){
      struct network_event_t new_net_event;
      __builtin_memset(&new_net_event, 0, sizeof(new_net_event));
      new_net_event.pid = pid;
      new_net_event.last_sent = now;
      new_net_event.proto = proto;
      new_net_event.type = type;
      new_net_event.family = fam;

      if (type == EVENT_SEND_BYTES){
          new_net_event.bytes_sent = slen;
      } else {
          new_net_event.bytes_recv = slen;
      }

      int ret = 0;
      if (proto == IPPROTO_TCP){
          ret = bpf_map_update_elem(&tcpBytesMap, &pid_tgid, &new_net_event, BPF_ANY);
      } else if (proto == IPPROTO_UDP){
          ret = bpf_map_update_elem(&udpBytesMap, &pid_tgid, &new_net_event, BPF_ANY);
      }
      if (ret != 0){
        char x[] = "transfer bytes, unable to update map, proto: %d, error: %d\n";
        bpf_trace_printk(x, sizeof(x), proto, ret);
      }
      bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &new_net_event, sizeof(new_net_event));
      return 0;
  }
  u64 diff = now - net_event->last_sent;

  net_event->pid = pid;
  net_event->family = fam;
  if (type == EVENT_SEND_BYTES){
      __sync_fetch_and_add(&net_event->bytes_sent, slen);
  } else {
      __sync_fetch_and_add(&net_event->bytes_recv, slen);
  }

  if (diff > 1e9 * 2) {
    net_event->last_sent = now;
    net_event->pid = pid;
    net_event->proto = proto;
    net_event->type = type;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, net_event, sizeof(*net_event));

    // once sent to userspace, reset counters
    if (type == EVENT_SEND_BYTES){
        net_event->bytes_sent = 0;
    } else {
        net_event->bytes_recv = 0;
    }
  }

  if (proto == IPPROTO_TCP){
      bpf_map_update_elem(&tcpBytesMap, &pid_tgid, net_event, BPF_ANY);
  } else if (proto == IPPROTO_UDP){
      bpf_map_update_elem(&udpBytesMap, &pid_tgid, net_event, BPF_ANY);
  }

  return 0;
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

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
    struct network_event_t *tcp_net_event = (struct network_event_t *)bpf_map_lookup_elem(&tcpBytesMap, &pid_tgid);
    struct network_event_t *udp_net_event = (struct network_event_t *)bpf_map_lookup_elem(&udpBytesMap, &pid_tgid);
    if (tcp_net_event != NULL){
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, tcp_net_event, sizeof(*tcp_net_event));
    }
    if (udp_net_event != NULL){
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, udp_net_event, sizeof(*udp_net_event));
    }


    bpf_map_delete_elem(&tcpBytesMap, &pid);
    bpf_map_delete_elem(&udpBytesMap, &pid);
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


SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg(struct pt_regs *ctx)
{
  __handle_transfer_bytes(ctx, IPPROTO_TCP, 0x0, EVENT_SEND_BYTES);
  return 0;
};

SEC("kretprobe/tcp_recvmsg")
int kretprobe__tcp_recvmsg(struct pt_regs *ctx)
{
  __handle_transfer_bytes(ctx, IPPROTO_TCP, 0x0, EVENT_RECV_BYTES);
  return 0;
};

SEC("kretprobe/udp_sendmsg")
int kretprobe__udp_sendmsg(struct pt_regs *ctx)
{
  __handle_transfer_bytes(ctx, IPPROTO_UDP, AF_INET, EVENT_SEND_BYTES);
  return 0;
};

SEC("kretprobe/udp_recvmsg")
int kretprobe__udp_recvmsg(struct pt_regs *ctx)
{
  __handle_transfer_bytes(ctx, IPPROTO_UDP, AF_INET, EVENT_RECV_BYTES);
  return 0;
};

SEC("kretprobe/udpv6_sendmsg")
int kretprobe__udpv6_sendmsg(struct pt_regs *ctx)
{
  __handle_transfer_bytes(ctx, IPPROTO_UDP, 0xa, EVENT_SEND_BYTES);
  return 0;
};

SEC("kretprobe/udpv6_recvmsg")
int kretprobe__udpv6_recvmsg(struct pt_regs *ctx)
{
  __handle_transfer_bytes(ctx, IPPROTO_UDP, 0xa, EVENT_RECV_BYTES);
  return 0;
};

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx)
{
    __handle_destroy_sock(ctx, IPPROTO_TCP, 0x0);

    return 0;
}


// SEC("kprobe/release_sock")
// SEC("kprobe/inet_sock_destruct")

/**
 * tcp_v4_destroy_sock also used for tcpv6?
 * https://elixir.bootlin.com/linux/latest/source/net/ipv6/tcp_ipv6.c#L2150
 */
SEC("kprobe/tcp_v4_destroy_sock")
int kprobe__tcp_v4_destroy_sock(struct pt_regs *ctx)
{
    __handle_destroy_sock(ctx, 0x0, 0x0);

    return 0;
}

SEC("kprobe/udp_abort")
int kprobe__udp_abort(struct pt_regs *ctx)
{
    __handle_destroy_sock(ctx, IPPROTO_UDP, AF_INET);

    return 0;
}

/**
 * udp_disconnect common for ipv4 and ipv6
 * https://elixir.bootlin.com/linux/latest/source/net/ipv6/udp.c#L1761
 */
SEC("kprobe/udp_disconnect")
int kprobe__udp_disconnect(struct pt_regs *ctx)
{
    __handle_destroy_sock(ctx, IPPROTO_UDP, 0x0);

    return 0;
}

SEC("kprobe/udp_destruct_sock")
int kprobe__udp_destruct_sock(struct pt_regs *ctx)
{
    __handle_destroy_sock(ctx, IPPROTO_UDP, AF_INET);

    return 0;
}

SEC("kprobe/udpv6_destruct_sock")
int kprobe__udpv6_destruct_sock(struct pt_regs *ctx)
{
    __handle_destroy_sock(ctx, IPPROTO_UDP, AF_INET6);

    return 0;
}


char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;
