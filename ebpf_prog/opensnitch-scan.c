/*
 * OpenSnitch - inbound port scan detection, kernel side.
 *
 * This program runs at TC ingress and turns inbound packets into compact
 * "probe" records for the userspace detection engine in daemon/portscan.
 *
 * ---------------------------------------------------------------------------
 * Why TC ingress rather than XDP
 * ---------------------------------------------------------------------------
 * XDP is faster, but it is the wrong trade for a desktop firewall:
 *
 *  - a laptop has Wi-Fi, VPN tunnels (tun, wireguard), Docker bridges and
 *    veth pairs. XDP is unsupported or falls back to generic mode on most of
 *    them, losing the very advantage it was chosen for;
 *  - only one XDP program may own an interface, so OpenSnitch would conflict
 *    with any other XDP user on the machine. TCX (kernel >= 6.6) is built for
 *    multiple owners;
 *  - at TC ingress the Ethernet header is still present, which is what makes
 *    reporting the source MAC possible at all.
 *
 * ---------------------------------------------------------------------------
 * Why this program does NOT score
 * ---------------------------------------------------------------------------
 * The obvious design is to run the whole detection algorithm here, and it is
 * the design flowhawk chose. It is a mistake for this project, for one reason:
 * the scoring logic would then exist twice, once in C and once in Go, and the
 * two copies would have to stay bit-identical forever for the AF_PACKET
 * fallback and the eBPF path to agree. Every future threshold change would be
 * two changes, and a divergence would be invisible until it produced a wrong
 * verdict in production.
 *
 * So the split is by *what each side is good at*:
 *
 *   kernel  - cheap, per-packet, high-volume work: parse the headers, drop
 *             everything structurally uninteresting, and rate-limit what is
 *             left so a flood cannot drown the ring buffer.
 *   user    - the stateful judgement: scoring, decay, deduplication, naming
 *             the technique. One implementation, already covered by the
 *             differential harness.
 *
 * The result is that both packet sources emit the same Probe stream, so their
 * verdicts are identical by construction rather than by two implementations
 * being kept in step by hand.
 *
 * ---------------------------------------------------------------------------
 * Portability
 * ---------------------------------------------------------------------------
 * Unlike opensnitch.c, this program reads no kernel-internal structure: it
 * touches only struct __sk_buff (uapi, stable) and the packet bytes. It
 * therefore needs no kernel headers and no per-kernel rebuild -- one object
 * works across kernel versions, which the kprobe modules cannot do.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

/* Keep in step with daemon/portscan: these values are part of the contract
 * between the two halves and are checked by a test on the Go side. */
#define PROBE_ANOMALY_FRAGMENT       (1 << 0)
#define PROBE_ANOMALY_EXTHDR_CHAIN   (1 << 1)
#define PROBE_ANOMALY_TRUNCATED      (1 << 2)
#define PROBE_ANOMALY_NO_TCP_OPTIONS (1 << 3)
/* These exist in daemon/portscan/probe.go too, and must match:
 * TestEbpfContractConstantsMatchC requires every anomaly bit on both sides. */
#define PROBE_ANOMALY_FIRST_FRAGMENT (1 << 4)
#define PROBE_ANOMALY_VLAN_DEPTH     (1 << 5)
#define PROBE_ANOMALY_TRAILER        (1 << 6)

#define PROBE_FLAG_HAS_MAC     (1 << 0)
#define PROBE_FLAG_TCP_FLAGS_OK (1 << 1)
#define PROBE_FLAG_IPV6        (1 << 2)

/* maxExtHeaders in daemon/portscan/parse.go. The verifier forbids an unbounded
 * loop, so kernel and userspace must agree on the same bound or they would
 * disagree about long chains. Exceeding it is reported, never swallowed: a
 * chain this long is itself an evasion signature (Topera hides the TCP header
 * behind seven or more empty extension headers for exactly this reason). */
#define MAX_EXT_HEADERS 8
#define MAX_VLAN_TAGS   2

/* maxExtChainBytes in daemon/portscan/parse.go. Counting headers alone bounds
 * nothing useful: one Destination Options header may declare 2048 bytes, so
 * eight of them reach 16 KB. That figure is what the AF_PACKET fallback has to
 * size its capture buffer against, and getting it wrong made a 200-byte option
 * header a complete evasion of that path. Both sides carry the same value. */
#define MAX_EXT_CHAIN_BYTES 1024

/* ICMPv6 is not in <linux/in.h>, which only covers the IPv4 protocol
 * numbers. Spelled out here rather than pulled from another header, so the
 * program keeps compiling against nothing but what it already includes. */
#define IPPROTO_ICMPV6 58

/* IPv6 extension header numbers, per RFC 8200 section 4.1. */
#define IPV6_EXT_HOPOPTS   0
#define IPV6_EXT_ROUTING  43
#define IPV6_EXT_FRAGMENT 44
#define IPV6_EXT_ESP      50
#define IPV6_EXT_AH       51
#define IPV6_NO_NEXT      59
#define IPV6_EXT_DSTOPTS  60
#define IPV6_EXT_MOBILITY 135
#define IPV6_EXT_HIP      139
#define IPV6_EXT_SHIM6    140

/*
 * probe_event is the record handed to userspace. It mirrors, field for field,
 * what daemon/portscan.Probe needs; the Go side decodes it with a matching
 * struct and a compile-time size assertion.
 */
struct probe_event {
    __u64 time_ns;
    __u8  saddr[16];   /* IPv4 is stored as a v4-mapped address */
    __u8  daddr[16];
    __u8  src_mac[6];
    __u16 sport;
    __u16 dport;
    __u32 ifindex;
    __u8  proto;
    __u8  tcp_flags;
    __u16 anomalies;
    __u16 flags;
    __u16 pad;
} __attribute__((packed));

/* Per-source forwarding budget. Without it, a 65535-port scan would push one
 * record per packet into the ring buffer; the engine needs only enough probes
 * to cross its threshold and characterise the technique. */
struct source_budget {
    __u64 window_start_ns;
    __u32 sent;
    __u32 dropped;
};

/* An LPM key for the never-count prefix list, filled from userspace. */
struct lpm_key_v4 {
    __u32 prefixlen;
    __u8  addr[4];
};

struct lpm_key_v6 {
    __u32 prefixlen;
    __u8  addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} scan_events SEC(".maps");

/* Per-source forwarding budget, in a shared LRU. A per-CPU LRU
 * (BPF_F_NO_COMMON_LRU) would split max_entries between CPUs -- 512 sources per
 * CPU on a sixteen-core desktop -- making a source's own budget entry cheap to
 * evict and its ceiling cheap to lift. Contention is not an issue: insertions are
 * capped by the aggregate budget (see budgets_check), and a hit allocates
 * nothing. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u8[16]);
    __type(value, struct source_budget);
} source_budgets SEC(".maps");

/* The global forwarding budget, one entry per CPU. The per-source budget
 * bounds nothing in aggregate: a flood of forged sources is a stream of first
 * packets. Per-CPU rather than one contended counter, so the ceiling is
 * budget * ncpu. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct source_budget);
} global_budget SEC(".maps");

/* Addresses of this host, filled by the daemon. Only packets aimed at one of
 * them are considered, which discards broadcast, multicast and transit traffic
 * in one test. Sized like the exemption tries: an address missing from this map
 * is one for which nothing is detected, and a container host has one per veth
 * plus rotating IPv6 privacy addresses. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u8[16]);
    __type(value, __u8);
} local_addrs SEC(".maps");

/* Interfaces that carry no link-layer header, by index.
 *
 * A tun device, ppp0, sit0, gre or an xfrm interface is ARPHRD_NONE: the frame
 * this program sees begins at the IP header, with no Ethernet header in front of
 * it. Filled by the daemon from the interfaces that have no hardware address,
 * and refreshed with them, because a VPN comes and goes. See tc_scan_ingress. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} l2less_ifaces SEC(".maps");

/* Never-count prefixes, filled by the daemon (SystemHostInfo.ExemptPrefixes):
 * loopback, multicast and the limited broadcast address, plus the operator's
 * PortScan.NeverCount. Never-block addresses -- link-local ranges, gateways,
 * resolvers -- are not here: their packets must still be counted, and only the
 * firewall rule is refused, in user space. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_key_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} exempt_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_key_v6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} exempt_v6 SEC(".maps");

/* Destination ports never counted: DHCP, NetBIOS, mDNS, SSDP, LLMNR, from
 * Config.ExcludedPorts. A bitmap in an ARRAY, not a HASH: the verifier turns an
 * array lookup into direct indexing, where a hash lookup is a real call on
 * every TCP or UDP packet aimed at this host. 65536 bits is 8 KB and cannot fill
 * up. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} excluded_ports SEC(".maps");

#define CFG_ENABLED        0
#define CFG_MAX_PER_SEC    1
/* CFG_MAX_TOTAL_PER_SEC bounds forwarding across ALL sources, per CPU. */
#define CFG_MAX_TOTAL_PER_SEC 4
#define CFG_GRACE_UNTIL_LO 2
#define CFG_GRACE_UNTIL_HI 3
#define CFG_NCONFIG        8

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CFG_NCONFIG);
    __type(key, __u32);
    __type(value, __u32);
} scan_config SEC(".maps");

#define STAT_SEEN      0
#define STAT_FORWARDED 1
#define STAT_FILTERED  2
/* STAT_RATELIMIT counts refusals by the aggregate budget, which cost every
 * source its probes; STAT_SRCLIMIT those by a source's own budget, which cost
 * only that source. One peer's download goes past its own budget, and counted
 * together that read as detection degraded for everyone. */
#define STAT_RATELIMIT 3
#define STAT_NORINGBUF 4
#define STAT_SRCLIMIT  5
#define STAT_NSTATS    8

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_NSTATS);
    __type(key, __u32);
    __type(value, __u64);
} scan_stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&scan_stats, &idx);
    if (v)
        (*v)++;
}

static __always_inline __u32 cfg(__u32 idx, __u32 dflt)
{
    __u32 *v = bpf_map_lookup_elem(&scan_config, &idx);
    return v ? *v : dflt;
}

/* is_v4_mapped reports whether a 16-byte key holds an IPv4 address in the
 * ::ffff:a.b.c.d form. The maps are keyed by address form while the packet has a
 * family: an exempt IPv4 prefix lives in exempt_v4, and an IPv6 packet written
 * ::ffff:192.168.1.1 must be looked up there, not in exempt_v6. */
static __always_inline int is_v4_mapped(const __u8 a[16])
{
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 &&
           a[4] == 0 && a[5] == 0 && a[6] == 0 && a[7] == 0 &&
           a[8] == 0 && a[9] == 0 && a[10] == 0xff && a[11] == 0xff;
}

/* v4_mapped writes an IPv4 address as ::ffff:a.b.c.d, so a single 16-byte key
 * covers both families and the maps need no per-family duplication. */
static __always_inline void v4_mapped(__u8 out[16], __u32 be_addr)
{
    __builtin_memset(out, 0, 10);
    out[10] = 0xff;
    out[11] = 0xff;
    __builtin_memcpy(out + 12, &be_addr, 4);
}

static __always_inline int is_ipv6_ext(__u8 nh)
{
    /* ESP (50) is deliberately absent: everything past it is encrypted, so
     * there is no transport header to find and skipping it would mean parsing
     * ciphertext as a TCP header. */
    return nh == IPV6_EXT_HOPOPTS || nh == IPV6_EXT_ROUTING ||
           nh == IPV6_EXT_FRAGMENT || nh == IPV6_EXT_AH ||
           nh == IPV6_EXT_DSTOPTS || nh == IPV6_EXT_MOBILITY ||
           nh == IPV6_EXT_HIP || nh == IPV6_EXT_SHIM6;
}

/* ext_header_len returns the size of an IPv6 extension header. Three
 * conventions coexist:
 *   - Fragment (44): fixed 8 octets, its second byte reserved;
 *   - Authentication Header (51): (len + 2) * 4 (RFC 4302 2.2);
 *   - everything else: (len + 1) * 8 (RFC 8200 4.3); 0 is a valid 8-byte
 *     header, not an error. */
static __always_inline int ext_header_len(__u8 this_hdr, __u8 hdr_ext_len)
{
    if (this_hdr == IPV6_EXT_FRAGMENT)
        return 8;
    if (this_hdr == IPV6_EXT_AH)
        return ((int)hdr_ext_len + 2) * 4;
    return ((int)hdr_ext_len + 1) * 8;
}

/* read_byte safely fetches one byte at off, or returns -1. */
static __always_inline int read_byte(struct __sk_buff *skb, __u32 off, __u8 *out)
{
    if (bpf_skb_load_bytes(skb, off, out, 1) < 0)
        return -1;
    return 0;
}

/* parse_transport reads the TCP or UDP header.
 *
 * avail is how many bytes the IP header declares are left for the transport
 * layer, not how many the frame holds: Ethernet pads short frames, and a byte
 * of padding read as the flag octet would report flags never on the wire -- or
 * flags an on-link sender chose, RST included. TC ingress runs before ip_rcv()
 * trims the frame, so this program bounds the read itself. A first fragment
 * from nmap -f carries the ports and not the flags; PROBE_FLAG_TCP_FLAGS_OK
 * tells user space which. */
static __always_inline void parse_transport(struct __sk_buff *skb, __u32 off,
                                            __u32 avail, struct probe_event *ev)
{
    if (ev->proto == IPPROTO_TCP) {
        __u8 hdr[20];
        if (avail >= 20 && bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) == 0) {
            ev->sport = bpf_ntohs(*(__u16 *)&hdr[0]);
            ev->dport = bpf_ntohs(*(__u16 *)&hdr[2]);
            ev->tcp_flags = hdr[13];
            ev->flags |= PROBE_FLAG_TCP_FLAGS_OK;
            __u32 data_off = (hdr[12] >> 4) * 4;
            if (data_off < 20 || data_off > avail) {
                /* The header declares a length that is malformed or reaches
                 * past what arrived. The ports and flags were genuinely read
                 * and are kept; what is not known is whether anything followed
                 * them. Saying so is what stops the next test -- "no options,
                 * therefore masscan" -- from being drawn from a field nobody
                 * checked. parseTransport makes the same call. */
                ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
                return;
            }
            /* A SYN with no options at all is not what a real stack emits: it
             * always advertises at least an MSS. psad uses the same signal to
             * recognise masscan. */
            if ((hdr[13] & 0x02) && data_off == 20)
                ev->anomalies |= PROBE_ANOMALY_NO_TCP_OPTIONS;
            return;
        }
        /* Short: a truncated first fragment still carries the ports, and the flags
         * if the header reaches 14 bytes (they are the 13th octet). Salvage what is
         * present and say so. parseTransport in parse.go makes the same two cuts. */
        ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
        __u8 part[14];
        if (avail >= 14 && bpf_skb_load_bytes(skb, off, part, sizeof(part)) == 0) {
            ev->sport = bpf_ntohs(*(__u16 *)&part[0]);
            ev->dport = bpf_ntohs(*(__u16 *)&part[2]);
            ev->tcp_flags = part[13];
            ev->flags |= PROBE_FLAG_TCP_FLAGS_OK;
        } else if (avail >= 4 && bpf_skb_load_bytes(skb, off, part, 4) == 0) {
            ev->sport = bpf_ntohs(*(__u16 *)&part[0]);
            ev->dport = bpf_ntohs(*(__u16 *)&part[2]);
        }
        return;
    }
    if (ev->proto == IPPROTO_UDP) {
        __u8 hdr[8];
        if (avail >= 8 && bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) == 0) {
            ev->sport = bpf_ntohs(*(__u16 *)&hdr[0]);
            ev->dport = bpf_ntohs(*(__u16 *)&hdr[2]);
            return;
        }
        ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
        return;
    }
    if (ev->proto == IPPROTO_ICMP || ev->proto == IPPROTO_ICMPV6) {
        /* The message type and code, packed into dport as type<<8|code, the
         * convention the kernel's connection tracking uses. User space deduplicates by
         * (protocol, dport), so an ICMP source scores once per distinct type, not per
         * packet. parseTransport reads the same two bytes into the same field. */
        __u8 hdr[2];
        if (avail >= 2 && bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) == 0) {
            ev->dport = ((__u16)hdr[0] << 8) | hdr[1];
            return;
        }
        ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
        return;
    }
    /* Any other protocol has no ports. It is still meaningful: an nmap -sO
     * scan is exactly a stream of these, and userspace counts distinct
     * protocol numbers to detect it. */
}

static __always_inline int parse_ipv4(struct __sk_buff *skb, __u32 off,
                                      struct probe_event *ev,
                                      __u32 *t_off, __u32 *t_avail, int *t_ok)
{
    __u8 hdr[20];
    if (bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) < 0) {
        ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
        return -1;
    }
    __u32 ihl = (hdr[0] & 0x0f) * 4;
    /* A header shorter than the minimum is malformed; trusting it would make
     * the transport offset point back inside the IP header. flowhawk computes
     * the L4 offset from ihl without ever checking it. */
    if (ihl < 20)
        return -1;

    ev->proto = hdr[9];
    v4_mapped(ev->saddr, *(__u32 *)&hdr[12]);
    v4_mapped(ev->daddr, *(__u32 *)&hdr[16]);

    __u16 frag_field = bpf_ntohs(*(__u16 *)&hdr[6]);
    if ((frag_field & 0x1fff) != 0) {
        /* A non-initial fragment has no transport header at any assumed
         * offset. scanlogd refuses these explicitly (scanlogd.c:208); reading
         * on would interpret payload bytes as ports and flags. */
        ev->anomalies |= PROBE_ANOMALY_FRAGMENT;
        return 0;
    }
    if (frag_field & 0x2000) {
        /* More Fragments on the first fragment: the ports are here, so this
         * still counts -- that is what makes nmap -f detectable -- but the
         * split is evidence in its own right. */
        ev->anomalies |= PROBE_ANOMALY_FIRST_FRAGMENT;
    }

    /* Bound the transport read by what the header DECLARES, never by what the
     * frame holds. See parse_transport. */
    __u32 tot_len = bpf_ntohs(*(__u16 *)&hdr[2]);
    if (tot_len < ihl) {
        /* A length shorter than the header it describes is malformed, and
         * trusting it would make the remaining length underflow. */
        ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
        return 0;
    }
    __u32 avail;
    if (off + tot_len > skb->len) {
        /* The datagram claims more than arrived: a snaplen cut, or a lying
         * header. Only the captured bytes exist, and saying so matters -- the
         * RST shortcut refuses to act on a truncated read, so a sender who
         * declares a length past the end of the frame must not thereby get a
         * clean bill of health on one path and a flagged one on the other.
         * ipPayload in parse.go marks exactly this case. */
        ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
        avail = (off + ihl < skb->len) ? skb->len - off - ihl : 0;
    } else {
        if (off + tot_len < skb->len)
            ev->anomalies |= PROBE_ANOMALY_TRAILER;
        avail = tot_len - ihl;
    }
    *t_off = off + ihl;
    *t_avail = avail;
    *t_ok = 1;
    return 0;
}

static __always_inline int parse_ipv6(struct __sk_buff *skb, __u32 off,
                                      struct probe_event *ev,
                                      __u32 *t_off, __u32 *t_avail, int *t_ok)
{
    __u8 hdr[40];
    if (bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) < 0) {
        ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
        return -1;
    }
    ev->flags |= PROBE_FLAG_IPV6;
    __builtin_memcpy(ev->saddr, &hdr[8], 16);
    __builtin_memcpy(ev->daddr, &hdr[24], 16);

    /* The end of the datagram, as the header declares it. Payload Length zero with
     * a Hop-by-Hop next header is the exception the kernel makes -- ip6_rcv_core()
     * trims only when (pkt_len || nexthdr != NEXTHDR_HOP) -- so such a packet
     * reaches TCP and is answered: the captured length is used for that one shape. */
    __u32 payload_len = bpf_ntohs(*(__u16 *)&hdr[4]);
    __u32 end;
    if (payload_len == 0 && hdr[6] == IPV6_EXT_HOPOPTS) {
        ev->anomalies |= PROBE_ANOMALY_EXTHDR_CHAIN;
        end = skb->len;
    } else {
        end = off + 40 + payload_len;
        if (end > skb->len) {
            /* The capture is shorter than the datagram claims. Same reasoning
             * as in parse_ipv4: the read is truncated, and both paths must say
             * so or the RST shortcut fires on one and not the other. */
            ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
            end = skb->len;
        } else if (end < skb->len) {
            ev->anomalies |= PROBE_ANOMALY_TRAILER;
        }
    }

    __u8 next = hdr[6];
    __u32 cur = off + 40;

#pragma unroll
    for (int i = 0; i < MAX_EXT_HEADERS; i++) {
        if (!is_ipv6_ext(next))
            goto done;

        if (cur - (off + 40) >= MAX_EXT_CHAIN_BYTES) {
            ev->anomalies |= PROBE_ANOMALY_EXTHDR_CHAIN;
            ev->proto = next;
            return 0;
        }

        /* Every read below is bounded by `end`, the length the header declares, not
         * only by the frame: an extension header overrunning the declared length stops
         * the walk on itself, as parseIPv6 does, so both sources report the same
         * protocol for the same bytes. */
        if (cur + 2 > end) {
            ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
            ev->proto = next;
            return 0;
        }
        __u8 nh, hlen;
        if (read_byte(skb, cur, &nh) < 0 || read_byte(skb, cur + 1, &hlen) < 0) {
            ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
            ev->proto = next;
            return 0;
        }
        if (next == IPV6_EXT_FRAGMENT) {
            __u8 fo[2];
            /* An offset field outside the capture is a truncation, not something to walk
             * past: parseIPv6 refuses it too. */
            if (cur + 4 > end || bpf_skb_load_bytes(skb, cur + 2, fo, 2) != 0) {
                ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
                ev->proto = next;
                return 0;
            }
            __u16 frag_off = (((__u16)fo[0] << 8) | fo[1]) >> 3;
            if (frag_off != 0) {
                ev->anomalies |= PROBE_ANOMALY_FRAGMENT;
                ev->proto = nh;
                return 0;
            }
        }
        int len = ext_header_len(next, hlen);
        if (len <= 0)
            break;
        /* The end of the chain is bounded, not only where each header starts:
         * one header may be 2048 bytes, and a TCP header past the AF_PACKET
         * snap length was read there as a truncated packet with no port. Same
         * test, same place, as parseIPv6. */
        if (cur + (__u32)len - (off + 40) > MAX_EXT_CHAIN_BYTES) {
            ev->anomalies |= PROBE_ANOMALY_EXTHDR_CHAIN;
            ev->proto = next;
            return 0;
        }
        if (cur + (__u32)len > end) {
            ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
            ev->proto = next;
            return 0;
        }
        cur += (__u32)len;
        next = nh;
    }

    /* The bounded walk was exhausted while still on extension headers: report
     * it rather than dropping the packet silently. */
    if (is_ipv6_ext(next)) {
        ev->anomalies |= PROBE_ANOMALY_EXTHDR_CHAIN;
        ev->proto = next;
        return 0;
    }

done:
    ev->proto = next;
    if (next == IPV6_NO_NEXT)
        return 0;
    if (cur >= end) {
        ev->anomalies |= PROBE_ANOMALY_TRUNCATED;
        return 0;
    }
    *t_off = cur;
    *t_avail = end - cur;
    *t_ok = 1;
    return 0;
}

/* window_rolled reports whether a one-second budget window that began at
 * window_start_ns has ended by now_ns. A timestamp slightly behind the window
 * start is cross-CPU skew, not a new window: bpf_ktime_get_ns is monotonic per
 * CPU, and a scan's packets land on every CPU because RSS hashes the destination
 * port. Rolling on every backward step granted a fresh budget several times a
 * second. A timestamp a whole window behind is a clock anomaly and does roll, or
 * the start would sit in the future and blind detection. Engine.windowRolled
 * is the Go half. */
static __always_inline int window_rolled(__u64 window_start_ns, __u64 now_ns)
{
    if (now_ns >= window_start_ns)
        return now_ns - window_start_ns >= 1000000000ULL;
    return window_start_ns - now_ns >= 1000000000ULL;
}

/* global_allow applies the per-CPU aggregate budget. For a source never seen
 * before it runs before the entry is created: a flood of forged sources is a
 * stream of first packets, which no per-source budget can bound. */
static __always_inline int global_allow(__u64 now_ns, __u32 max_per_sec)
{
    __u32 zero = 0;
    struct source_budget *g = bpf_map_lookup_elem(&global_budget, &zero);
    if (!g)
        return 1;  /* a PERCPU_ARRAY lookup cannot fail; fail open if it does */

    if (window_rolled(g->window_start_ns, now_ns)) {
        g->window_start_ns = now_ns;
        g->sent = 0;
        g->dropped = 0;
    }
    if (g->sent >= max_per_sec) {
        g->dropped++;
        return 0;
    }
    g->sent++;
    return 1;
}

/* What budgets_check decided. */
#define BUDGET_OK     0
#define BUDGET_SOURCE 1
#define BUDGET_TOTAL  2

/* budgets_check applies both budgets, in the order that makes each mean what it
 * claims, and says which one refused. A known source is judged by its own
 * budget first, and the aggregate is charged only for what survives it:
 * charged first, one flooding address would spend the whole aggregate on
 * packets its own budget refuses, and every other source that second would be
 * turned away -- a scan's few probes included. A source never seen before is
 * the exception: the aggregate is consulted before its entry is created, so a
 * forged-source flood cannot fill the LRU either. */
static __always_inline int budgets_check(__u8 key[16], __u64 now_ns,
                                         __u32 max_per_sec, __u32 max_total)
{
    struct source_budget *b = bpf_map_lookup_elem(&source_budgets, key);
    if (!b) {
        if (!global_allow(now_ns, max_total))
            return BUDGET_TOTAL;
        struct source_budget nb = {
            .window_start_ns = now_ns,
            .sent = 1,
            .dropped = 0,
        };
        bpf_map_update_elem(&source_budgets, key, &nb, BPF_ANY);
        return BUDGET_OK;
    }
    /* Every update below is atomic: the entry is shared between CPUs, and a scan's
     * packets are spread across all of them by RSS, so a plain b->sent++ loses
     * increments exactly while the counter ramps up. The window roll is a
     * compare-and-swap so that exactly one CPU resets the counter; a timestamp
     * that went backwards is guarded against, as scanlogd does for clock_t
     * wrap-around. */
    __u64 ws = b->window_start_ns;
    if (window_rolled(ws, now_ns)) {
        if (__sync_bool_compare_and_swap(&b->window_start_ns, ws, now_ns)) {
            /* This CPU owns the reset. It then falls through like everyone
             * else, so its own packet is counted once and charged to the
             * aggregate budget like any other -- taking the packet here and
             * returning early would have skipped that charge. */
            __sync_lock_test_and_set(&b->sent, 0);
            __sync_lock_test_and_set(&b->dropped, 0);
        }
    }
    /* Reserve the slot and read the old value in one operation. `sent` keeps
     * climbing past max_per_sec for the rest of the window, which is harmless:
     * it is compared, never displayed, and a u32 cannot wrap in a second at any
     * rate a NIC can deliver. */
    if (__sync_fetch_and_add(&b->sent, 1) >= max_per_sec) {
        __sync_fetch_and_add(&b->dropped, 1);
        return BUDGET_SOURCE;
    }
    /* Only now is the aggregate budget charged. A packet refused by it has
     * still consumed a per-source slot, which errs on the strict side for that
     * one source and never on the permissive side for the total. */
    return global_allow(now_ns, max_total) ? BUDGET_OK : BUDGET_TOTAL;
}

SEC("tc")
int tc_scan_ingress(struct __sk_buff *skb)
{
    if (!cfg(CFG_ENABLED, 0))
        return TC_ACT_OK;

    bump(STAT_SEEN);

    __u8 eth[14] = {};
    __u16 ethertype;
    __u32 off;
    int have_mac;

    /* A tun device (WireGuard, OpenVPN, Tailscale), ppp, sit, gre or xfrm has no
     * link header: the frame begins at the IP header. Which interfaces those are
     * is looked up before anything is read as Ethernet, never guessed from the
     * packet: on them, bytes 12-13 belong to the source address, which the
     * sender chooses, and 8.0.0.0/16 would read as an IPv4 ethertype. */
    __u32 ifindex = skb->ifindex;
    if (bpf_map_lookup_elem(&l2less_ifaces, &ifindex)) {
        /* skb->protocol is what the kernel itself determined the payload to be,
         * which on these devices is the only reliable source for it. */
        ethertype = bpf_ntohs((__u16)skb->protocol);
        if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6) {
            bump(STAT_FILTERED);
            return TC_ACT_OK;
        }
        off = 0;
        have_mac = 0;
    } else {
        if (bpf_skb_load_bytes(skb, 0, eth, sizeof(eth)) < 0)
            return TC_ACT_OK;
        ethertype = bpf_ntohs(*(__u16 *)&eth[12]);
        off = 14;
        have_mac = 1;

#pragma unroll
        for (int i = 0; i < MAX_VLAN_TAGS; i++) {
            if (ethertype != ETH_P_8021Q && ethertype != ETH_P_8021AD)
                break;
            __u8 tag[4];
            if (bpf_skb_load_bytes(skb, off, tag, sizeof(tag)) < 0)
                return TC_ACT_OK;
            ethertype = bpf_ntohs(*(__u16 *)&tag[2]);
            off += 4;
        }
        if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6) {
            bump(STAT_FILTERED);
            return TC_ACT_OK;
        }
    }

    struct probe_event ev = {};
    ev.ifindex = skb->ifindex;
    if (have_mac) {
        __builtin_memcpy(ev.src_mac, &eth[6], 6);
        ev.flags |= PROBE_FLAG_HAS_MAC;
    }

    __u32 t_off = 0, t_avail = 0;
    int t_ok = 0;
    int rc = (ethertype == ETH_P_IP) ? parse_ipv4(skb, off, &ev, &t_off, &t_avail, &t_ok)
                                     : parse_ipv6(skb, off, &ev, &t_off, &t_avail, &t_ok);
    if (rc < 0) {
        bump(STAT_FILTERED);
        return TC_ACT_OK;
    }

    /* Only packets aimed at one of our own unicast addresses. A v4-mapped address
     * in an IPv6 packet is refused on either side of the header: RFC 4291 2.5.5.2
     * keeps the form off the wire and ip6_rcv drops it, but TC ingress runs first.
     * As a destination it would pass the local-address test for a family the host
     * does not own it in; as a source, the unmapped record would get an IPv4
     * address blocked by IPv6 packets. parseIPv6 refuses the same shape. */
    if ((ev.flags & PROBE_FLAG_IPV6) &&
        (is_v4_mapped(ev.daddr) || is_v4_mapped(ev.saddr))) {
        bump(STAT_FILTERED);
        return TC_ACT_OK;
    }
    if (!bpf_map_lookup_elem(&local_addrs, ev.daddr)) {
        bump(STAT_FILTERED);
        return TC_ACT_OK;
    }

    /* Never-count sources. The trie is chosen by the FORM of the address, not
     * by the family of the packet: see is_v4_mapped. */
    if ((ev.flags & PROBE_FLAG_IPV6) && !is_v4_mapped(ev.saddr)) {
        struct lpm_key_v6 k6 = { .prefixlen = 128 };
        __builtin_memcpy(k6.addr, ev.saddr, 16);
        if (bpf_map_lookup_elem(&exempt_v6, &k6)) {
            bump(STAT_FILTERED);
            return TC_ACT_OK;
        }
    } else {
        struct lpm_key_v4 k4 = { .prefixlen = 32 };
        __builtin_memcpy(k4.addr, ev.saddr + 12, 4);
        if (bpf_map_lookup_elem(&exempt_v4, &k4)) {
            bump(STAT_FILTERED);
            return TC_ACT_OK;
        }
    }

    /* The transport header is read here, once the address-only filters have
     * passed: bpf_skb_load_bytes is a real helper call, and most packets -- not for
     * us, or from a never-count source -- never need it. */
    if (t_ok)
        parse_transport(skb, t_off, t_avail, &ev);

    /* Discovery protocols that legitimately touch several ports. */
    if (ev.proto == IPPROTO_TCP || ev.proto == IPPROTO_UDP) {
        __u32 word = (__u32)ev.dport >> 6;
        __u64 *bits = bpf_map_lookup_elem(&excluded_ports, &word);
        /* An ARRAY lookup cannot miss for an in-range key, and a __u16 shifted
         * right by six is always below 1024. The NULL test is kept because the
         * verifier requires it, not because it can fire. */
        if (bits && ((*bits >> (ev.dport & 63)) & 1)) {
            bump(STAT_FILTERED);
            return TC_ACT_OK;
        }
    }

    /* A packet carrying exactly RST or RST|ACK is a rejection, not a probe:
     * counting it would let anyone raise a source's score by bouncing traffic off
     * us. Exactly those two values -- nmap --scanflags ALL sets RST alongside
     * everything else -- and only when the flags were actually read, or a forged
     * RST in a fragmented scan's padding would drop the whole scan. Engine.classify
     * applies the same condition. */
    if (ev.proto == IPPROTO_TCP && (ev.flags & PROBE_FLAG_TCP_FLAGS_OK) &&
        !(ev.anomalies & (PROBE_ANOMALY_TRUNCATED | PROBE_ANOMALY_TRAILER)) &&
        (ev.tcp_flags == 0x04 || ev.tcp_flags == 0x14)) {
        bump(STAT_FILTERED);
        return TC_ACT_OK;
    }

    /* The clock is read here, after every structural filter: bpf_ktime_get_ns() is
     * a helper call, and packets that are not for us need no time. The grace
     * deadline, the budget windows and the record's timestamp all use this
     * reading. */
    ev.time_ns = bpf_ktime_get_ns();

    /* Startup grace: at daemon start, packets of connections opened before it
     * began tracking have no known owner and look like probes to closed ports.
     * CFG_GRACE_UNTIL_* is an absolute deadline in bpf_ktime_get_ns()'s clock,
     * written by the daemon. Only TCP carrying ACK can belong to such a
     * connection, so only that is spared, as in Engine.accept; sparing everything
     * would make the first minute after every boot blind to a SYN sweep. */
    __u64 grace = ((__u64)cfg(CFG_GRACE_UNTIL_HI, 0) << 32) | cfg(CFG_GRACE_UNTIL_LO, 0);
    if (ev.time_ns < grace && ev.proto == IPPROTO_TCP &&
        (ev.flags & PROBE_FLAG_TCP_FLAGS_OK) && (ev.tcp_flags & 0x10)) {
        bump(STAT_FILTERED);
        return TC_ACT_OK;
    }

    /* Both budgets, in the one order under which each means what it says. See
     * budgets_check. */
    int refused = budgets_check(ev.saddr, ev.time_ns,
                                cfg(CFG_MAX_PER_SEC, 256),
                                cfg(CFG_MAX_TOTAL_PER_SEC, 4096));
    if (refused != BUDGET_OK) {
        bump(refused == BUDGET_SOURCE ? STAT_SRCLIMIT : STAT_RATELIMIT);
        return TC_ACT_OK;
    }

    struct probe_event *out = bpf_ringbuf_reserve(&scan_events, sizeof(*out), 0);
    if (!out) {
        /* The ring buffer is full. Counting this is what lets the daemon say
         * "detection was degraded" instead of silently under-reporting. */
        bump(STAT_NORINGBUF);
        return TC_ACT_OK;
    }
    __builtin_memcpy(out, &ev, sizeof(ev));
    bpf_ringbuf_submit(out, 0);
    bump(STAT_FORWARDED);

    /* Detection never changes a verdict here. Blocking is applied by an
     * nftables rule the daemon installs, so it is visible to the user and to
     * any external audit, instead of being an invisible drop inside a BPF
     * program. */
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
