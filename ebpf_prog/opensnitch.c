#define KBUILD_MODNAME "dummy"

#include "common_defs.h"

struct tcp_key_t {
    u16 sport;
    u32 daddr;
    u16 dport;
    u32 saddr;
}__attribute__((packed));

struct tcp_value_t {
    pid_size_t pid;
    uid_size_t uid;
    char comm[TASK_COMM_LEN];
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
    char comm[TASK_COMM_LEN];
}__attribute__((packed));

struct udp_key_t {
    u16 sport;
    u32 daddr;
    u16 dport;
    u32 saddr;
} __attribute__((packed));

struct udp_value_t{
    pid_size_t pid;
    uid_size_t uid;
    char comm[TASK_COMM_LEN];
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
    char comm[TASK_COMM_LEN];
}__attribute__((packed));


// on x86_32 "struct sock" is arranged differently from x86_64 (at least on Debian kernels).
// We hardcode offsets of IP addresses.
struct sock_on_x86_32_t {
     u8 data_we_dont_care_about[40];
     struct ipV6 daddr;
     struct ipV6 saddr;
};


// Add +1,+2,+3 etc. to map size helps to easier distinguish maps in bpftool's output
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tcp_key_t);
    __type(value, struct tcp_value_t);
    __uint(max_entries, MAPSIZE+1);
} tcpMap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tcpv6_key_t);
    __type(value, struct tcpv6_value_t);
    __uint(max_entries, MAPSIZE+2);
} tcpv6Map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct udp_key_t);
    __type(value, struct udp_value_t);
    __uint(max_entries, MAPSIZE+3);
} udpMap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct udpv6_key_t);
    __type(value, struct udpv6_value_t);
    __uint(max_entries, MAPSIZE+4);
} udpv6Map SEC(".maps");

// for TCP the IP-tuple can be copied from "struct sock" only upon return from tcp_connect().
// We stash the socket here to look it up upon return.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    // using u64 instead of sizeof(struct sock *)
    // to avoid pointer size related quirks on x86_32
    __type(value, u64);
    __uint(max_entries, 300);
} tcpsock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 300);
} tcpv6sock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 300);
} icmpsock SEC(".maps");

// initializing variables with __builtin_memset() is required
// for compatibility with bpf on kernel 4.4

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_i386)
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

    struct tcp_value_t tcp_value={0};
    __builtin_memset(&tcp_value, 0, sizeof(tcp_value));
    tcp_value.pid = pid_tgid >> 32;
    tcp_value.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&tcp_value.comm, sizeof(tcp_value.comm));
    bpf_map_update_elem(&tcpMap, &tcp_key, &tcp_value, BPF_ANY);

    bpf_map_delete_elem(&tcpsock, &pid_tgid);
    return 0;
};

SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_i386)
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
#if defined(__TARGET_ARCH_i386)
    struct sock_on_x86_32_t sock;
    __builtin_memset(&sock, 0, sizeof(sock));
    bpf_probe_read(&sock, sizeof(sock), *(&sk));
    tcpv6_key.daddr = sock.daddr;
    tcpv6_key.saddr = sock.saddr;
#else
    bpf_probe_read(&tcpv6_key.daddr, sizeof(tcpv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    bpf_probe_read(&tcpv6_key.saddr, sizeof(tcpv6_key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
#endif

    struct tcpv6_value_t tcpv6_value={0};
    __builtin_memset(&tcpv6_value, 0, sizeof(tcpv6_value));
    tcpv6_value.pid = pid_tgid >> 32;
    tcpv6_value.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&tcpv6_value.comm, sizeof(tcpv6_value.comm));
    bpf_map_update_elem(&tcpv6Map, &tcpv6_key, &tcpv6_value, BPF_ANY);

    bpf_map_delete_elem(&tcpv6sock, &pid_tgid);
    return 0;
};

SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_i386)
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

    if (udp_key.saddr == 0){
        u64 cmsg=0;
        bpf_probe_read(&cmsg, sizeof(cmsg), &msg->msg_control);
        struct in_pktinfo *inpkt = (struct in_pktinfo *)CMSG_DATA(cmsg);
        bpf_probe_read(&udp_key.saddr, sizeof(udp_key.saddr), &inpkt->ipi_spec_dst.s_addr);
    }

    u32 zero_key = 0;
    __builtin_memset(&zero_key, 0, sizeof(zero_key));
    struct udp_value_t *lookedupValue = bpf_map_lookup_elem(&udpMap, &udp_key);
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (lookedupValue == NULL || lookedupValue->pid != pid) {
        struct udp_value_t udp_value={0};
        __builtin_memset(&udp_value, 0, sizeof(udp_value));
        udp_value.pid = pid;
        udp_value.uid = bpf_get_current_uid_gid() & 0xffffffff;
        bpf_get_current_comm(&udp_value.comm, sizeof(udp_value.comm));
        bpf_map_update_elem(&udpMap, &udp_key, &udp_value, BPF_ANY);
    }
    //else nothing to do
    return 0;
};


SEC("kprobe/udpv6_sendmsg")
int kprobe__udpv6_sendmsg(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_i386)
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

    if (udpv6_key.saddr.part1 == 0){
        u64 cmsg=0;
        bpf_probe_read(&cmsg, sizeof(cmsg), &msg->msg_control);
        struct in6_pktinfo *inpkt = (struct in6_pktinfo *)CMSG_DATA(cmsg);
        bpf_probe_read(&udpv6_key.saddr, sizeof(udpv6_key.saddr), &inpkt->ipi6_addr.in6_u.u6_addr32);
    }

#if defined(__TARGET_ARCH_i386)
    struct sock_on_x86_32_t sock;
    __builtin_memset(&sock, 0, sizeof(sock));
    bpf_probe_read(&sock, sizeof(sock), *(&sk));
    udpv6_key.daddr = sock.daddr;
    udpv6_key.saddr = sock.saddr;
#endif

    struct udpv6_value_t *lookedupValue = bpf_map_lookup_elem(&udpv6Map, &udpv6_key);
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (lookedupValue == NULL || lookedupValue->pid != pid) {
        struct udpv6_value_t udpv6_value={0};
        __builtin_memset(&udpv6_value, 0, sizeof(udpv6_value));
        bpf_get_current_comm(&udpv6_value.comm, sizeof(udpv6_value.comm));
        udpv6_value.pid = pid;
        udpv6_value.uid = bpf_get_current_uid_gid() & 0xffffffff;
        bpf_map_update_elem(&udpv6Map, &udpv6_key, &udpv6_value, BPF_ANY);
    }
    //else nothing to do
    return 0;
};

SEC("kprobe/udp_tunnel6_xmit_skb")
int kprobe__udp_tunnel6_xmit_skb(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_x86)
    struct sock *sk = (struct sock *)PT_REGS_PARM2(ctx);
    struct in6_addr *saddr = (struct in6_addr *)PT_REGS_PARM5(ctx);
    // 6th
    struct in6_addr *daddr = (struct in6_addr *)(ctx->r9);
    // 10th
    void *sport_ptr = (void *)(ctx->sp + 32);
    // 11th
    void *dport_ptr = (void *)(ctx->sp + 40);

    struct udpv6_key_t udpv6_key, udpv6_key2;
    __builtin_memset(&udpv6_key, 0, sizeof(udpv6_key));
    __builtin_memset(&udpv6_key2, 0, sizeof(udpv6_key2));
    u16 dport = 0, sport = 0;

    bpf_probe_read(&sport, sizeof(sport), (void *)sport_ptr);
    bpf_probe_read(&dport, sizeof(dport), (void *)dport_ptr);
    if (dport == 0 || sport == 0){
        return 0;
    }

    udpv6_key.dport = dport;
    udpv6_key.sport = (sport >> 8) | ((sport << 8) & 0xff00);
    udpv6_key2.sport = udpv6_key.sport;
    udpv6_key2.dport = udpv6_key.dport;

    // tunnel addrs
    bpf_probe_read(&udpv6_key.saddr, sizeof(udpv6_key.saddr), &saddr->in6_u.u6_addr32);
    bpf_probe_read(&udpv6_key.daddr, sizeof(udpv6_key.daddr), &daddr->in6_u.u6_addr32);

    //bpf_probe_read(&udpv6_key.dport, sizeof(udpv6_key.dport), &sk->__sk_common.skc_dport);
    //bpf_probe_read(&udpv6_key.sport, sizeof(udpv6_key.sport), &sk->__sk_common.skc_num);

    // internet addrs
    bpf_probe_read(&udpv6_key2.daddr, sizeof(udpv6_key2.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    bpf_probe_read(&udpv6_key2.saddr, sizeof(udpv6_key2.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
    struct udpv6_value_t udpv6_value={0};
    __builtin_memset(&udpv6_value, 0, sizeof(udpv6_value));
    bpf_get_current_comm(&udpv6_value.comm, sizeof(udpv6_value.comm));
    udpv6_value.pid = pid;
    udpv6_value.uid = bpf_get_current_uid_gid() & 0xffffffff;

    struct udpv6_value_t *lookedupValue = bpf_map_lookup_elem(&udpv6Map, &udpv6_key2);
    if (lookedupValue == NULL || lookedupValue->pid != pid) {
        bpf_map_update_elem(&udpv6Map, &udpv6_key2, &udpv6_value, BPF_ANY);
    }

    lookedupValue = bpf_map_lookup_elem(&udpv6Map, &udpv6_key);
    if (lookedupValue == NULL || lookedupValue->pid != pid) {
        bpf_map_update_elem(&udpv6Map, &udpv6_key, &udpv6_value, BPF_ANY);
    }

    // when saddr and daddr are empty, usually the connection is from-to localhost.
    if (saddr == 0 && daddr == 0){
        udpv6_key.saddr.part1 = 0;
        udpv6_key.saddr.part2 = htonll(1);
        udpv6_key.daddr.part1 = 0;
        udpv6_key.daddr.part2 = htonll(1);
        bpf_map_update_elem(&udpv6Map, &udpv6_key, &udpv6_value, BPF_ANY);
    }

#endif

    // TODO: other architectures

    return 0;
};


SEC("kprobe/inet_dgram_connect")
int kprobe__inet_dgram_connect(struct pt_regs *ctx)
{
    struct socket *skt = (struct socket *)PT_REGS_PARM1(ctx);
    struct sockaddr *saddr = (struct sockaddr *)PT_REGS_PARM2(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 skp = (u64)skt;
    u64 sa = (u64)saddr;
    bpf_map_update_elem(&tcpsock, &pid_tgid, &skp, BPF_ANY);
    bpf_map_update_elem(&icmpsock, &pid_tgid, &sa, BPF_ANY);
    return 0;
}

SEC("kretprobe/inet_dgram_connect")
int kretprobe__inet_dgram_connect(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *skp = bpf_map_lookup_elem(&tcpsock, &pid_tgid);
    if (skp == NULL) { goto out; }
    u64 *sap = bpf_map_lookup_elem(&icmpsock, &pid_tgid);
    if (sap == NULL) { goto out; }

    struct sock *sk=NULL;
    struct socket *skt=NULL;
    __builtin_memset(&skt, 0, sizeof(skt));
    skt = (struct socket *)*skp;
    bpf_probe_read(&sk, sizeof(sk), &skt->sk);

    u8 proto = 0;
    u8 type = 0;
    u8 fam = 0;
    bpf_probe_read(&proto, sizeof(proto), &sk->sk_protocol);
    bpf_probe_read(&type, sizeof(type), &sk->sk_type);
    bpf_probe_read(&fam, sizeof(fam), &sk->__sk_common.skc_family);

    struct udp_value_t udp_value={0};
    __builtin_memset(&udp_value, 0, sizeof(udp_value));
    udp_value.pid = pid_tgid >> 32;
    udp_value.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&udp_value.comm, sizeof(udp_value.comm));

    if (fam == AF_INET){
        struct sockaddr_in *ska;
        struct udp_key_t udp_key;
        __builtin_memset(&ska, 0, sizeof(ska));
        __builtin_memset(&udp_key, 0, sizeof(udp_key));
        ska = (struct sockaddr_in *)*sap;

        // this is in reality the daddr
        bpf_probe_read(&udp_key.daddr, sizeof(udp_key.daddr), &ska->sin_addr.s_addr);
        bpf_probe_read(&udp_key.dport, sizeof(udp_key.dport), &ska->sin_port);
        if (udp_key.dport == 0){
            bpf_probe_read(&udp_key.dport, sizeof(udp_key.dport), &sk->__sk_common.skc_dport);
            bpf_probe_read(&udp_key.daddr, sizeof(udp_key.daddr), &sk->__sk_common.skc_daddr);
        }
        bpf_probe_read(&udp_key.sport, sizeof(udp_key.sport), &sk->__sk_common.skc_num);
        bpf_probe_read(&udp_key.saddr, sizeof(udp_key.saddr), &sk->__sk_common.skc_rcv_saddr);

        udp_key.sport = (udp_key.sport >> 8) | ((udp_key.sport << 8) & 0xff00);

        // There're several reasons for these fields to be empty:
        // - saddr may be empty if sk_state is 7 (CLOSE)
        // - <insert more here>
        if (udp_key.dport == 0 || udp_key.daddr == 0){
            goto out;
        }

        if (proto == IPPROTO_UDP){
            bpf_map_update_elem(&udpMap, &udp_key, &udp_value, BPF_ANY);
        }
    } else if (fam == AF_INET6){
        struct sockaddr_in6 *ska;
        struct udpv6_key_t udpv6_key;
        __builtin_memset(&ska, 0, sizeof(ska));
        __builtin_memset(&udpv6_key, 0, sizeof(udpv6_key));
        ska = (struct sockaddr_in6 *)*sap;

        bpf_probe_read(&udpv6_key.dport, sizeof(udpv6_key.dport), &sk->__sk_common.skc_dport);
        if (udpv6_key.dport != 0){ //likely
            bpf_probe_read(&udpv6_key.daddr, sizeof(udpv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        }
        else {
            bpf_probe_read(&udpv6_key.dport, sizeof(udpv6_key.dport), &ska->sin6_port);
            bpf_probe_read(&udpv6_key.daddr, sizeof(udpv6_key.daddr), &ska->sin6_addr.in6_u.u6_addr32);
        }

        bpf_probe_read(&udpv6_key.sport, sizeof(udpv6_key.sport), &sk->__sk_common.skc_num);
        bpf_probe_read(&udpv6_key.saddr, sizeof(udpv6_key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

#if defined(__TARGET_ARCH_i386)
        struct sock_on_x86_32_t sock;
        __builtin_memset(&sock, 0, sizeof(sock));
        bpf_probe_read(&sock, sizeof(sock), *(&sk));
        udpv6_key.daddr = sock.daddr;
        udpv6_key.saddr = sock.saddr;
#endif

        if (udpv6_key.dport == 0){
            goto out;
        }

        if (proto == IPPROTO_UDP){
            bpf_map_update_elem(&udpv6Map, &udpv6_key, &udp_value, BPF_ANY);
        }
    }
    //if (proto == IPPROTO_UDP && type == SOCK_DGRAM && udp_key.dport == 1025){
    //    udp_key.dport = 0;
    //    udp_key.sport = 0;
    //    bpf_map_update_elem(&icmpMap, &udp_key, &udp_value, BPF_ANY);
    //}
    //else if (proto == IPPROTO_UDP && type == SOCK_DGRAM && udp_key.dport != 1025){
    //    bpf_map_update_elem(&icmpMap, &udp_key, &udp_value, BPF_ANY);
    //} else if (proto == IPPROTO_TCP && type == SOCK_RAW){
    //    sport always 6 and dport 0
    //    bpf_map_update_elem(&tcpMap, &udp_key, &udp_value, BPF_ANY);
    //}

    return 0;
out:
    bpf_map_delete_elem(&tcpsock, &pid_tgid);
    bpf_map_delete_elem(&icmpsock, &pid_tgid);

    return 0;
};

SEC("kprobe/iptunnel_xmit")
int kprobe__iptunnel_xmit(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    u32 src = (u32)PT_REGS_PARM4(ctx);
    u32 dst = 0;
    u16 sport = 0;
    struct udp_key_t udp_key;
    struct udp_value_t udp_value;
    u16 pkt_hdr = 0;
    bpf_probe_read(&pkt_hdr, sizeof(pkt_hdr), &skb->transport_header);

#if defined(__TARGET_ARCH_i386)
    dst = (u32)(ctx->sp + 20);
#else
    dst = (u32)PT_REGS_PARM5(ctx);
#endif

#if defined(__TARGET_ARCH_i386) || defined(__TARGET_ARCH_arm)
    unsigned char *data=NULL;
    bpf_probe_read(&data, sizeof(data), &skb->data);
    unsigned char *udp_start = data + pkt_hdr;

    bpf_probe_read(&sport, sizeof(sport), udp_start);
    bpf_probe_read(&udp_key.dport, sizeof(udp_key.dport), &udp_start+2);
#else
    unsigned char *head;
    struct udphdr *udph;
    __builtin_memset(&udph, 0, sizeof(udph));
    __builtin_memset(&head, 0, sizeof(head));

    bpf_probe_read(&head, sizeof(head), &skb->head);
    udph = (struct udphdr *)(head + pkt_hdr);
    bpf_probe_read(&sport, sizeof(sport), &udph->source);
    bpf_probe_read(&udp_key.dport, sizeof(udp_key.dport), &udph->dest);
#endif
    sport = (sport >> 8) | ((sport << 8) & 0xff00);

    bpf_probe_read(&udp_key.sport, sizeof(udp_key.sport), &sport);
    bpf_probe_read(&udp_key.saddr, sizeof(udp_key.saddr), &src);
    bpf_probe_read(&udp_key.daddr, sizeof(udp_key.daddr), &dst);

    struct udp_value_t *lookedupValue = bpf_map_lookup_elem(&udpMap, &udp_key);
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (lookedupValue == NULL || lookedupValue->pid != pid) {
        bpf_get_current_comm(&udp_value.comm, sizeof(udp_value.comm));
        udp_value.pid = pid;
        udp_value.uid = bpf_get_current_uid_gid() & 0xffffffff;
        bpf_map_update_elem(&udpMap, &udp_key, &udp_value, BPF_ANY);
    }

    return 0;
};


char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;
