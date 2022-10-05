#define KBUILD_MODNAME "dummy"

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <net/sock.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

#define MAX_ALIASES 5
#define MAX_IPS 5

struct nameLookupEvent {
    u32 addr_type;
    u8 ip[16];
    char host[252];
} __attribute__((packed));

struct hostent {
    char *h_name;       /* Official name of host.  */
    char **h_aliases;   /* Alias list.  */
    int h_addrtype;     /* Host address type.  */
    int h_length;       /* Length of address.  */
    char **h_addr_list; /* List of addresses from name server.  */
#ifdef __USE_MISC
#define h_addr h_addr_list[0] /* Address, for backward compatibility.*/
#endif
};

struct addrinfo {
    int ai_flags;             /* Input flags.  */
    int ai_family;            /* Protocol family for socket.  */
    int ai_socktype;          /* Socket type.  */
    int ai_protocol;          /* Protocol for socket.  */
    size_t ai_addrlen;        /* Length of socket address.  */
    struct sockaddr *ai_addr; /* Socket address for socket.  */
    char *ai_canonname;       /* Canonical name for service location.  */
    struct addrinfo *ai_next; /* Pointer to next in list.  */
};

struct addrinfo_args_cache {
    struct addrinfo **addrinfo_ptr;
    char node[256];
};
// define temporary array for data
struct bpf_map_def SEC("maps/addrinfo_args_hash") addrinfo_args_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = MAPSIZE,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct addrinfo_args_cache),
};

// BPF output events
struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = MAPSIZE,
};

/**
 * Hooks gethostbyname calls and emits multiple nameLookupEvent events.
 * It supports at most MAX_IPS many addresses.
 */
SEC("uretprobe/gethostbyname")
int uretprobe__gethostbyname(struct pt_regs *ctx) {
    // bpf_tracing_prinkt("Called gethostbyname %d\n",1);
    struct nameLookupEvent data = {0};

    if (!PT_REGS_RC(ctx))
        return 0;

    struct hostent *host = (struct hostent *)PT_REGS_RC(ctx);
	char * hostnameptr;
	bpf_probe_read(&hostnameptr, sizeof(hostnameptr), &host->h_name);
    bpf_probe_read_str(&data.host, sizeof(data.host), hostnameptr);

    char **ips;
    bpf_probe_read(&ips, sizeof(ips), &host->h_addr_list);
#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_IPS; i++) {
        char *ip;
        bpf_probe_read(&ip, sizeof(ip), &ips[i]);

        if (ip == NULL) {
            return 0;
        }
        bpf_probe_read_user(&data.addr_type, sizeof(data.addr_type),
                            &host->h_addrtype);

        if (data.addr_type == AF_INET) {
            // Only copy the 4 relevant bytes
            bpf_probe_read_user(&data.ip, 4, ip);
        } else {
            bpf_probe_read_user(&data.ip, sizeof(data.ip), ip);
        }

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data,
                              sizeof(data));

        // char **alias = host->h_aliases;
        char **aliases;
        bpf_probe_read(&aliases, sizeof(aliases), &host->h_aliases);

#pragma clang loop unroll(full)
        for (int j = 0; j < MAX_ALIASES; j++) {
            char *alias;
            bpf_probe_read(&alias, sizeof(alias), &aliases[i]);

            if (alias == NULL) {
                return 0;
            }
            bpf_probe_read_user(&data.host, sizeof(data.host), alias);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data,
                                  sizeof(data));
        }
    }

    return 0;
}

// capture getaddrinfo call and store the relevant arguments to a hash.
SEC("uprobe/getaddrinfo")
int addrinfo(struct pt_regs *ctx) {
    struct addrinfo_args_cache addrinfo_args = {0};
    if (!PT_REGS_PARM1(ctx))
        return 0;
    if (!PT_REGS_PARM4(ctx))
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    addrinfo_args.addrinfo_ptr = (struct addrinfo **)PT_REGS_PARM4(ctx);

    bpf_probe_read_user_str(&addrinfo_args.node, sizeof(addrinfo_args.node),
                            (char *)PT_REGS_PARM1(ctx));

    bpf_map_update_elem(&addrinfo_args_hash, &tid, &addrinfo_args,
                        0 /* flags */);

    return 0;
}

SEC("uretprobe/getaddrinfo")
int ret_addrinfo(struct pt_regs *ctx) {
    struct nameLookupEvent data = {0};
    struct addrinfo_args_cache *addrinfo_args = {0};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    addrinfo_args = bpf_map_lookup_elem(&addrinfo_args_hash, &tid);

    if (addrinfo_args == 0) {
        return 0; // missed start
    }

    struct addrinfo **res_p;
    bpf_probe_read(&res_p, sizeof(res_p), &addrinfo_args->addrinfo_ptr);

#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_IPS; i++) {
        struct addrinfo *res;
        bpf_probe_read(&res, sizeof(res), res_p);
        if (res == NULL) {
            return 0;
        }
        bpf_probe_read(&data.addr_type, sizeof(data.addr_type),
                       &res->ai_family);

        if (data.addr_type == AF_INET) {
            struct sockaddr_in *ipv4;
            bpf_probe_read(&ipv4, sizeof(ipv4), &res->ai_addr);
            // Only copy the 4 relevant bytes
            bpf_probe_read_user(&data.ip, 4, &ipv4->sin_addr);
        } else if(data.addr_type == AF_INET6) {
            struct sockaddr_in6 *ipv6;
            bpf_probe_read(&ipv6, sizeof(ipv6), &res->ai_addr);

            bpf_probe_read_user(&data.ip, sizeof(data.ip), &ipv6->sin6_addr);
        } else {
			return 1;
		}

        bpf_probe_read_kernel_str(&data.host, sizeof(data.host),
                                  &addrinfo_args->node);

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data,
                              sizeof(data));


		struct addrinfo * next;
        bpf_probe_read(&next, sizeof(next), &res->ai_next);
		res_p = &next;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0xFFFFFFFE;
