/*
 * A stand-in for libbpf's <bpf/bpf_helpers.h>, so that ebpf_prog/opensnitch-scan.c
 * -- unmodified, byte for byte the file that is loaded into the kernel -- can be
 * compiled and RUN as an ordinary native program.
 *
 * Why this exists
 * ---------------
 * The tree carries two independent implementations of the same packet parsing:
 * the kernel one in C, and daemon/portscan's in Go for the AF_PACKET fallback.
 * The design says their verdicts agree by construction. Nothing checked it, and
 * three security fixes were consequently applied to the Go side alone -- bounding
 * the transport read by the DECLARED IP length, the first-fragment marker, and
 * the RST condition -- while the kernel path, which is the DEFAULT path, kept the
 * defect. A LAN scan with `nmap -f -sS` scored zero on a machine where eBPF was
 * working exactly as designed. The differential harness could not see any of it:
 * it only ever replayed the corpus through ParseEthernet.
 *
 * Compiling the real C, rather than reimplementing it here, is the entire point.
 * A reimplementation would be written by whoever holds the misconception that
 * produced the divergence, and would agree with it.
 *
 * What is faithful and what is not
 * --------------------------------
 * bpf_skb_load_bytes reproduces the kernel's bounds check exactly, because every
 * divergence found so far has been about how many bytes the program believes it
 * may read. That one is load-bearing.
 *
 * Maps and the ring buffer are delegated to the harness (cparse.c), which gives
 * scan_config just CFG_ENABLED and lets every other lookup miss, so the program
 * runs on its compiled-in defaults. The verdict path is therefore real: the
 * grace window, the v4-mapped destination refusal, the RST shortcut and both
 * rate limiters all execute. Only the map CONTENTS are stubbed, and the
 * userspace side that fills them is tested separately.
 */
#ifndef PORTSCAN_SHIM_BPF_HELPERS_H
#define PORTSCAN_SHIM_BPF_HELPERS_H

#include <linux/bpf.h>
#include <string.h>

#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

/* libbpf's map-definition macros expand to anonymous struct members whose TYPE
 * carries the value; only the declaration matters here, never the layout. */
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/*
 * Harness hooks. Defined in cparse.c, which includes the program source, so
 * these resolve within one translation unit and the maps -- file-scope objects
 * in the program -- are addressable for identity comparison.
 */
extern const unsigned char *shim_pkt;      /* current frame */
extern unsigned int shim_pkt_len;
extern void *shim_map_lookup(const void *map, const void *key);
extern void shim_ringbuf_submitted(const void *rec, unsigned long size);
extern unsigned long long shim_now_ns;

static __always_inline long bpf_skb_load_bytes(const struct __sk_buff *skb,
                                               __u32 offset, void *to, __u32 len)
{
    /* The kernel's own check, in the kernel's own arithmetic: an offset past
     * the end, or a length that would run past it, fails -- and the subtraction
     * is ordered so that it cannot wrap. Getting this wrong in either direction
     * would make the harness lie about the very thing it exists to measure. */
    (void)skb;
    if (offset > shim_pkt_len || len > shim_pkt_len - offset)
        return -1;
    memcpy(to, shim_pkt + offset, len);
    return 0;
}

static __always_inline void *bpf_map_lookup_elem(const void *map, const void *key)
{
    return shim_map_lookup(map, key);
}

static __always_inline long bpf_map_update_elem(const void *map, const void *key,
                                                const void *value, __u64 flags)
{
    (void)map; (void)key; (void)value; (void)flags;
    return 0;
}

static __always_inline __u64 bpf_ktime_get_ns(void) { return shim_now_ns; }

/* One record in flight at a time, which is all tc_scan_ingress ever reserves. */
extern unsigned char shim_ringbuf_slot[256];

static __always_inline void *bpf_ringbuf_reserve(const void *rb, __u64 size, __u64 flags)
{
    (void)rb; (void)flags;
    if (size > sizeof(shim_ringbuf_slot))
        return 0;
    return shim_ringbuf_slot;
}

static __always_inline void bpf_ringbuf_submit(void *data, __u64 flags)
{
    (void)flags;
    shim_ringbuf_submitted(data, sizeof(shim_ringbuf_slot));
}

#endif /* PORTSCAN_SHIM_BPF_HELPERS_H */
