#define KBUILD_MODNAME "dummy"

//uncomment if building on x86_32
//#define OPENSNITCH_x86_32

#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h> 
#include <net/sock.h>
#include <net/inet_sock.h>

#define MAPSIZE 12000

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
//-----------------------------------

// even though we only need 32 bits of pid, on x86_32 ebpf verifier complained when pid type was set to u32
typedef u64 pid_size_t;
typedef u64 uid_size_t; 

struct tcp_key_t {
	u16 sport;
	u32 daddr;
	u16 dport;
	u32 saddr;
}__attribute__((packed));

struct tcp_value_t{
	pid_size_t pid;
	uid_size_t uid;
	u64 counter;
}__attribute__((packed));

// not using unsigned __int128 because it is not supported on x86_32
struct ipV6 {
	u64 part1;
	u64 part2;
}__attribute__((packed));

struct tcpv6_key_t {
	u16 sport;
	struct ipV6 daddr;
	u16 dport;
	struct ipV6 saddr;
}__attribute__((packed));

struct tcpv6_value_t{
	pid_size_t pid;
	uid_size_t uid;
	u64 counter; 
}__attribute__((packed));;

struct udp_key_t {
	u16 sport;
	u32 daddr;
	u16 dport;
	u32 saddr; 
} __attribute__((packed));

struct udp_value_t{
	pid_size_t pid;
	uid_size_t uid;
	u64 counter; 
}__attribute__((packed));

struct udpv6_key_t {
	u16 sport;
	struct ipV6 daddr;
	u16 dport;
	struct ipV6 saddr; 
}__attribute__((packed));

struct udpv6_value_t{
	pid_size_t pid;
	uid_size_t uid;
	u64 counter;
}__attribute__((packed));

// on x86_32 "struct sock" is arranged differently from x86_64 (at least on Debian kernels).
// We hardcode offsets of IP addresses.
struct sock_on_x86_32_t {
	 u8 data_we_dont_care_about[40];
	 struct ipV6 daddr;
	 struct ipV6 saddr;
};


// Add +1,+2,+3 etc. to map size helps to easier distinguish maps in bpftool's output
struct bpf_map_def SEC("maps/tcpMap") tcpMap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcp_key_t),
	.value_size = sizeof(struct tcp_value_t),
	.max_entries = MAPSIZE+1,
};
struct bpf_map_def SEC("maps/tcpv6Map") tcpv6Map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcpv6_key_t),
	.value_size = sizeof(struct tcpv6_value_t),
	.max_entries = MAPSIZE+2,
};
struct bpf_map_def SEC("maps/udpMap") udpMap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct udp_key_t),
	.value_size = sizeof(struct udp_value_t),
	.max_entries = MAPSIZE+3,
};
struct bpf_map_def SEC("maps/udpv6Map") udpv6Map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct udpv6_key_t),
	.value_size = sizeof(struct udpv6_value_t),
	.max_entries = MAPSIZE+4,
};

// for TCP the IP-tuple can be copied from "struct sock" only upon return from tcp_connect().
// We stash the socket here to look it up upon return.
struct bpf_map_def SEC("maps/tcpsock") tcpsock = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),// using u64 instead of sizeof(struct sock *) 
							  // to avoid pointer size related quirks on x86_32
	.max_entries = 100,
};
struct bpf_map_def SEC("maps/tcpv6sock") tcpv6sock = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),
	.max_entries = 100,
};

// //counts how many connections we've processed. Starts at 0.
struct bpf_map_def SEC("maps/tcpcounter") tcpcounter = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};
struct bpf_map_def SEC("maps/tcpv6counter") tcpv6counter = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};
struct bpf_map_def SEC("maps/udpcounter") udpcounter = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};
struct bpf_map_def SEC("maps/udpv6counter") udpv6counter = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};
struct bpf_map_def SEC("maps/debugcounter") debugcounter = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};

// size 150 gave ebpf verifier errors for kernel 4.14, 100 is ok
// we can cast any struct into rawBytes_t to be able to access arbitrary bytes of the struct 
struct rawBytes_t {
    u8 bytes[100];
};


//used for debug purposes only
struct bpf_map_def SEC("maps/bytes") bytes = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 222,
};

//used for debug purposes only
struct bpf_map_def SEC("maps/debug") debug = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcpv6_key_t),
	.value_size = sizeof(struct rawBytes_t),
	.max_entries = 555,
};


// initializing variables with __builtin_memset() is required
// for compatibility with bpf on kernel 4.4

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	#ifdef OPENSNITCH_x86_32
	// On x86_32 platforms I couldn't get function arguments using PT_REGS_PARM1
	// that's why we are accessing registers directly
		struct sock *sk = (struct sock *)((ctx)->ax);
	#else 
		struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	#endif

	u64 skp = (u64)sk;
	u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcpsock, &pid_tgid, &skp, BPF_ANY);
	return 0;
};


SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 *skp = bpf_map_lookup_elem(&tcpsock, &pid_tgid);
	if (skp == NULL) {return 0;}

	struct sock *sk;
	__builtin_memset(&sk, 0, sizeof(sk));
	sk = (struct sock *)*skp;

	struct tcp_key_t tcp_key;
    __builtin_memset(&tcp_key, 0, sizeof(tcp_key));
	bpf_probe_read(&tcp_key.dport, sizeof(tcp_key.dport), &sk->__sk_common.skc_dport);
	bpf_probe_read(&tcp_key.sport, sizeof(tcp_key.sport), &sk->__sk_common.skc_num);
	bpf_probe_read(&tcp_key.daddr, sizeof(tcp_key.daddr), &sk->__sk_common.skc_daddr);
	bpf_probe_read(&tcp_key.saddr, sizeof(tcp_key.saddr), &sk->__sk_common.skc_rcv_saddr);
	
	u32 zero_key = 0;
	u64 *val = bpf_map_lookup_elem(&tcpcounter, &zero_key);
	if (val == NULL){return 0;}

	struct tcp_value_t tcp_value;
	__builtin_memset(&tcp_value, 0, sizeof(tcp_value));
	tcp_value.pid = pid_tgid >> 32;
	tcp_value.uid = bpf_get_current_uid_gid() & 0xffffffff;
	tcp_value.counter = *val;
	bpf_map_update_elem(&tcpMap, &tcp_key, &tcp_value, BPF_ANY);
	u64 newval = *val + 1;
	bpf_map_update_elem(&tcpcounter, &zero_key, &newval, BPF_ANY);
	bpf_map_delete_elem(&tcpsock, &pid_tgid);
	return 0;
};


SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	#ifdef OPENSNITCH_x86_32
		struct sock *sk = (struct sock *)((ctx)->ax);
	#else
		struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	#endif

	u64 skp = (u64)sk;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&tcpv6sock, &pid_tgid, &skp, BPF_ANY);
	return 0;
};
SEC("kretprobe/tcp_v6_connect")
int kretprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 *skp = bpf_map_lookup_elem(&tcpv6sock, &pid_tgid);
	if (skp == NULL) {return 0;}
	struct sock *sk;
	__builtin_memset(&sk, 0, sizeof(sk));
	sk = (struct sock *)*skp;
	
	struct tcpv6_key_t tcpv6_key;
    __builtin_memset(&tcpv6_key, 0, sizeof(tcpv6_key));
	bpf_probe_read(&tcpv6_key.dport, sizeof(tcpv6_key.dport), &sk->__sk_common.skc_dport);
	bpf_probe_read(&tcpv6_key.sport, sizeof(tcpv6_key.sport), &sk->__sk_common.skc_num);
	#ifdef OPENSNITCH_x86_32
		struct sock_on_x86_32_t sock;
    	__builtin_memset(&sock, 0, sizeof(sock));
    	bpf_probe_read(&sock, sizeof(sock), *(&sk));
		tcpv6_key.daddr = sock.daddr;
		tcpv6_key.saddr = sock.saddr;
	#else
		bpf_probe_read(&tcpv6_key.daddr, sizeof(tcpv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		bpf_probe_read(&tcpv6_key.saddr, sizeof(tcpv6_key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	#endif

	u32 zero_key = 0;
	u64 *val = bpf_map_lookup_elem(&tcpv6counter, &zero_key);
	if (val == NULL){return 0;}

	struct tcpv6_value_t tcpv6_value;
    __builtin_memset(&tcpv6_value, 0, sizeof(tcpv6_value));
	tcpv6_value.pid = pid_tgid >> 32;
	tcpv6_value.uid = bpf_get_current_uid_gid() & 0xffffffff;
	tcpv6_value.counter = *val;
	bpf_map_update_elem(&tcpv6Map, &tcpv6_key, &tcpv6_value, BPF_ANY);
	u64 newval = *val + 1;
	bpf_map_update_elem(&tcpv6counter, &zero_key, &newval, BPF_ANY);
	bpf_map_delete_elem(&tcpv6sock, &pid_tgid);
	return 0;
};


SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx)
{
	#ifdef OPENSNITCH_x86_32
		struct sock *sk = (struct sock *)((ctx)->ax);
		struct msghdr *msg = (struct msghdr *)((ctx)->dx);
	#else
		struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
		struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	#endif

	u64 msg_name; //pointer
    __builtin_memset(&msg_name, 0, sizeof(msg_name));
	bpf_probe_read(&msg_name, sizeof(msg_name), &msg->msg_name);
	struct sockaddr_in * usin = (struct sockaddr_in *)msg_name;

	struct udp_key_t udp_key;
    __builtin_memset(&udp_key, 0, sizeof(udp_key));
	bpf_probe_read(&udp_key.dport, sizeof(udp_key.dport), &usin->sin_port);
	if (udp_key.dport != 0){ //likely
		bpf_probe_read(&udp_key.daddr, sizeof(udp_key.daddr), &usin->sin_addr.s_addr);
	}
	else {
		//very rarely dport can be found in skc_dport 
		bpf_probe_read(&udp_key.dport, sizeof(udp_key.dport), &sk->__sk_common.skc_dport);
		bpf_probe_read(&udp_key.daddr, sizeof(udp_key.daddr), &sk->__sk_common.skc_daddr);
	}
	bpf_probe_read(&udp_key.sport, sizeof(udp_key.sport), &sk->__sk_common.skc_num);
	bpf_probe_read(&udp_key.saddr, sizeof(udp_key.saddr), &sk->__sk_common.skc_rcv_saddr);
	
	u32 zero_key = 0;
    __builtin_memset(&zero_key, 0, sizeof(zero_key));
	u64 *counterVal = bpf_map_lookup_elem(&udpcounter, &zero_key);
	if (counterVal == NULL){return 0;}
	struct udp_value_t *lookedupValue = bpf_map_lookup_elem(&udpMap, &udp_key);
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	if ( lookedupValue == NULL || lookedupValue->pid != pid) {
		struct udp_value_t udp_value;
        __builtin_memset(&udp_value, 0, sizeof(udp_value));
		udp_value.pid = pid;
		udp_value.uid = bpf_get_current_uid_gid() & 0xffffffff;
		udp_value.counter = *counterVal;
		bpf_map_update_elem(&udpMap, &udp_key, &udp_value, BPF_ANY);
		u64 newval = *counterVal + 1;
		bpf_map_update_elem(&udpcounter, &zero_key, &newval, BPF_ANY);
	}
	//else nothing to do
	return 0;

};


SEC("kprobe/udpv6_sendmsg")
int kprobe__udpv6_sendmsg(struct pt_regs *ctx)
{	
	#ifdef OPENSNITCH_x86_32
		struct sock *sk = (struct sock *)((ctx)->ax);
		struct msghdr *msg = (struct msghdr *)((ctx)->dx);
	#else
		struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
		struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	#endif

	u64 msg_name; //a pointer
    __builtin_memset(&msg_name, 0, sizeof(msg_name));
	bpf_probe_read(&msg_name, sizeof(msg_name), &msg->msg_name);

	struct udpv6_key_t udpv6_key;
    __builtin_memset(&udpv6_key, 0, sizeof(udpv6_key));
	bpf_probe_read(&udpv6_key.dport, sizeof(udpv6_key.dport), &sk->__sk_common.skc_dport);
	if (udpv6_key.dport != 0){ //likely
		bpf_probe_read(&udpv6_key.daddr, sizeof(udpv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	else {
		struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *)msg_name;
		bpf_probe_read(&udpv6_key.dport, sizeof(udpv6_key.dport), &sin6->sin6_port);
		bpf_probe_read(&udpv6_key.daddr, sizeof(udpv6_key.daddr), &sin6->sin6_addr.in6_u.u6_addr32);
	}

	bpf_probe_read(&udpv6_key.sport, sizeof(udpv6_key.sport), &sk->__sk_common.skc_num);
	bpf_probe_read(&udpv6_key.saddr, sizeof(udpv6_key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);


	#ifdef OPENSNITCH_x86_32
		struct sock_on_x86_32_t sock;
    	__builtin_memset(&sock, 0, sizeof(sock));
    	bpf_probe_read(&sock, sizeof(sock), *(&sk));
		udpv6_key.daddr = sock.daddr;
		udpv6_key.saddr = sock.saddr;
	#endif

	u32 zero_key = 0;
	u64 *counterVal = bpf_map_lookup_elem(&udpv6counter, &zero_key);
	if (counterVal == NULL){return 0;}
	struct udpv6_value_t *lookedupValue = bpf_map_lookup_elem(&udpv6Map, &udpv6_key);
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	if ( lookedupValue == NULL || lookedupValue->pid != pid) {
		struct udpv6_value_t udpv6_value;
        __builtin_memset(&udpv6_value, 0, sizeof(udpv6_value));
		udpv6_value.pid = pid;
		udpv6_value.uid = bpf_get_current_uid_gid() & 0xffffffff;
		udpv6_value.counter = *counterVal;
		bpf_map_update_elem(&udpv6Map, &udpv6_key, &udpv6_value, BPF_ANY);
		u64 newval = *counterVal + 1;
		bpf_map_update_elem(&udpv6counter, &zero_key, &newval, BPF_ANY);	
	}
	//else nothing to do
	return 0;
	
};

// debug only: increment key's value by 1 in map "bytes"
void increment(u32 key){
	u32 *lookedupValue = bpf_map_lookup_elem(&bytes, &key);
	if (lookedupValue == NULL){
		u32 zero = 0;
		bpf_map_update_elem(&bytes, &key, &zero, BPF_ANY);
	}
	else {
		u32 newval = *lookedupValue + 1;
		bpf_map_update_elem(&bytes, &key, &newval, BPF_ANY);
	}
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;
