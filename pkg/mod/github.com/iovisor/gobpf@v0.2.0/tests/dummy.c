/*
 * Compiled with './build'
 */

#include "../elf/include/uapi/linux/bpf.h"
#include "../elf/include/bpf_map.h"

#define SEC(NAME) __attribute__((section(NAME), used))

#define PERF_MAX_STACK_DEPTH 127

#define KERNEL_VERSION_GTE(X) (KERNEL_VERSION >= X)

struct pt_regs{};

struct bpf_map_def SEC("maps/dummy_hash") dummy_hash = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 128,
};

struct bpf_map_def SEC("maps/dummy_array") dummy_array = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 128,
};

struct bpf_map_def SEC("maps/dummy_prog_array") dummy_prog_array = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 128,
};

struct bpf_map_def SEC("maps/dummy_perf") dummy_perf = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 128,
};

#if KERNEL_VERSION_GTE(46)
struct bpf_map_def SEC("maps/dummy_percpu_hash") dummy_percpu_hash = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 128,
};

struct bpf_map_def SEC("maps/dummy_percpu_array") dummy_percpu_array = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 128,
};

struct bpf_map_def SEC("maps/dummy_stack_trace") dummy_stack_trace = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(int),
	.value_size = PERF_MAX_STACK_DEPTH * sizeof(unsigned long long),
	.max_entries = 128,
};
#endif

#if KERNEL_VERSION_GTE(48)
struct bpf_map_def SEC("maps/dummy_cgroup_array") dummy_cgroup_array = {
	.type = BPF_MAP_TYPE_CGROUP_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 128,
};
#endif

struct bpf_map_def SEC("maps/dummy_array_custom") dummy_array_custom = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 128,
	.pinning = PIN_CUSTOM_NS,
};

SEC("kprobe/dummy")
int kprobe__dummy(struct pt_regs *ctx)
{
	return 0;
}

SEC("kretprobe/dummy")
int kretprobe__dummy(struct pt_regs *ctx)
{
	return 0;
}

SEC("uprobe/dummy")
int uprobe__dummy(struct pt_regs *ctx)
{
	return 0;
}

SEC("uretprobe/dummy")
int uretprobe__dummy(struct pt_regs *ctx)
{
	return 0;
}

#if KERNEL_VERSION_GTE(410)
SEC("cgroup/skb")
int cgroup_skb__dummy(struct __sk_buff *skb)
{
	return 1;
}

SEC("cgroup/sock")
int cgroup_sock__dummy(struct __sk_buff *skb)
{
	return 0;
}
#endif

#if KERNEL_VERSION_GTE(47)
SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_sys_enter()
{
	return 0;
}
#endif

SEC("socket/dummy")
int socket__dummy(struct __sk_buff *skb)
{
	return 0;
}

#if KERNEL_VERSION_GTE(48)
SEC("xdp/prog1")
int xdp_drop(struct xdp_md *ctx) {
    return XDP_DROP;
}

SEC("xdp/prog2")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}
#endif

unsigned int _version SEC("version") = 0xFFFFFFFE;
