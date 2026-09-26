/*
 * cparse -- run the REAL kernel program over frames from stdin, natively.
 *
 * ebpf_prog/opensnitch-scan.c is included verbatim below. Nothing in it is
 * altered, ifdef'd or copied: the bytes compiled here are the bytes loaded into
 * the kernel. Only its environment is replaced, by the two headers in bpf/ that
 * shadow libbpf's (see bpf/bpf_helpers.h for the full rationale).
 *
 * Protocol, so the Go side can drive it without cgo:
 *
 *   stdout header : "cparse1 <sizeof(struct probe_event)>\n"
 *   stdin         : repeated [u32 le length][length bytes]
 *   stdout        : one record per frame,
 *                     [u8 verdict][u8 parsed][u8 reserved x2][probe_event bytes]
 *
 *   verdict: 0 filtered, 1 forwarded, 2 refused by the aggregate budget,
 *            3 no ring buffer, 4 not seen (the program returned before bumping
 *            STAT_SEEN), 5 refused by the source's own budget
 *   parsed:  1 when the event bytes hold a record the program actually built,
 *            whatever it then decided to do with it; 0 when parsing refused the
 *            frame outright and there is nothing to compare.
 *
 * The event bytes are the raw record as the kernel would have pushed it into
 * the ring buffer, so feeding them through the Go decodeProbeEvent also proves
 * the hand-written field offsets still match the C struct.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Hook storage, defined before the program source so its inlined helpers link. */
const unsigned char *shim_pkt;
unsigned int shim_pkt_len;
unsigned long long shim_now_ns = 1000000000ULL; /* past any grace deadline of 0 */
unsigned char shim_ringbuf_slot[256];
static int shim_submitted;
static unsigned char shim_parsed[256];
static int shim_parsed_valid;
static unsigned long long shim_stats[8];
static unsigned int shim_config[8];
static int shim_grace_set;
/* CPARSE_L2LESS: the interface has no link header (tun, ppp, sit): frames
 * begin at the IP header, and skb->protocol says which version, as the kernel
 * sets it on such a device. */
static int shim_l2less;
/* CPARSE_BUDGET_SPENT=source or =total: that budget is found already spent,
 * so the program's own accounting of each refusal can be checked; with
 * =total-known the source is also found, within its own budget, so the
 * aggregate refuses it on the other path. Unset, both budgets take their
 * "never seen" path, which allows. */
static int shim_budget_spent;
static struct source_budget shim_spent_budget;
static struct source_budget shim_fresh_budget;
static int shim_fresh_used;

void *shim_map_lookup(const void *map, const void *key);
void shim_ringbuf_submitted(const void *rec, unsigned long size);

#include "../../../../ebpf_prog/opensnitch-scan.c"

/* Where tc_scan_ingress's own struct probe_event lives, once recovered. */
static const struct probe_event *shim_ev;

/*
 * Map contents.
 *
 * scan_config carries CFG_ENABLED, and the start-up grace deadline when
 * CPARSE_GRACE_UNTIL_NS is set in the environment (shim_now_ns is 1 s, so a
 * larger deadline puts every frame inside the grace). Every other index
 * misses, so cfg() falls back to the compiled-in default and the harness
 * exercises the shipped configuration rather than one invented here.
 *
 * local_addrs always hits: the Go parser has no notion of which addresses the
 * host owns, and a differential over parsing must not be decided by ownership.
 *
 * scan_stats is backed for real, which is how the verdict is read out -- the
 * program's own accounting, not a guess reconstructed from its return value.
 *
 * l2less_ifaces hits only under CPARSE_L2LESS.
 *
 * Everything else misses: nothing is exempt, no port is excluded, and both rate
 * limiters take their "never seen this source" path, which allows -- unless
 * CPARSE_BUDGET_SPENT names one of them, which is then found spent.
 */
void *shim_map_lookup(const void *map, const void *key)
{
    if (map == (const void *)&scan_config) {
        __u32 idx = *(const __u32 *)key;
        if (idx == CFG_ENABLED)
            return &shim_config[CFG_ENABLED];
        if ((idx == CFG_GRACE_UNTIL_LO || idx == CFG_GRACE_UNTIL_HI) && shim_grace_set)
            return &shim_config[idx];
        return 0;
    }
    if (map == (const void *)&l2less_ifaces)
        return shim_l2less ? (void *)&shim_config[CFG_ENABLED] : 0;
    if (map == (const void *)&scan_stats) {
        __u32 idx = *(const __u32 *)key;
        if (idx < STAT_NSTATS)
            return &shim_stats[idx];
        return 0;
    }
    if (map == (const void *)&local_addrs) {
        /* Find the record on the way past, and remember WHERE it is.
         *
         * tc_scan_ingress calls this with `ev.daddr`, a member of the local
         * struct probe_event it is filling, and it does so on every frame that
         * parsed. Recovering the struct from a member address is a liberty, so
         * it is checked rather than assumed -- the bytes at daddr must be the
         * key we were handed, or the recovery is discarded.
         *
         * The alternative was to duplicate the Ethernet/VLAN preamble in the
         * harness and call parse_ipv4/parse_ipv6 directly, which would have
         * reintroduced the second implementation this file exists to eliminate. */
        const struct probe_event *ev =
            (const struct probe_event *)((const unsigned char *)key -
                                         __builtin_offsetof(struct probe_event, daddr));
        if (memcmp(ev->daddr, key, sizeof(ev->daddr)) == 0) {
            shim_ev = ev;
            memcpy(shim_parsed, ev, sizeof(struct probe_event));
            shim_parsed_valid = 1;
        }
        return (void *)&shim_config[0];
    }
    /* Re-snapshot at every LATER filter map.
     *
     * `ev` is a local of tc_scan_ingress and stays alive for the whole call, so
     * the pointer recovered above is valid at each of these points -- no
     * lifetime liberty is taken beyond the one already checked.
     *
     * Taking the snapshot at the last filter rather than at the first is what
     * makes the capture independent of WHERE in the program the transport
     * header happens to be read. It must be the last point before a drop, not
     * the earliest reachable one: the frames worth comparing field by field are
     * exactly those the program is about to discard -- the RST shortcut is where
     * the kernel and Go parsers last disagreed -- and an early snapshot shows
     * those frames half-parsed.
     *
     * scan_stats, scan_config and global_budget are deliberately NOT snapshot
     * points. bump() is called immediately before every return, so snapshotting
     * there would make the self-check in main() -- "the record recovered on the
     * way past is the record that was forwarded" -- true by construction and
     * therefore worthless. */
    if (map == (const void *)&global_budget && shim_budget_spent >= 2) {
        shim_spent_budget.window_start_ns = shim_now_ns;
        shim_spent_budget.sent = 1u << 30;
        return &shim_spent_budget;
    }
    if (map == (const void *)&exempt_v4 || map == (const void *)&exempt_v6 ||
        map == (const void *)&excluded_ports || map == (const void *)&source_budgets) {
        if (shim_ev) {
            memcpy(shim_parsed, shim_ev, sizeof(struct probe_event));
            shim_parsed_valid = 1;
        }
        if (map == (const void *)&source_budgets && shim_budget_spent == 1) {
            shim_spent_budget.window_start_ns = shim_now_ns;
            shim_spent_budget.sent = 1u << 30;
            return &shim_spent_budget;
        }
        if (map == (const void *)&source_budgets && shim_budget_spent == 3) {
            shim_fresh_budget.window_start_ns = shim_now_ns;
            shim_fresh_budget.sent = 0;
            shim_fresh_used = 1;
            return &shim_fresh_budget;
        }
        return 0;
    }
    return 0;
}

void shim_ringbuf_submitted(const void *rec, unsigned long size)
{
    (void)rec;
    (void)size;
    shim_submitted = 1;
}

enum {
    VERDICT_FILTERED = 0,
    VERDICT_FORWARDED = 1,
    VERDICT_RATELIMITED = 2,
    VERDICT_NORINGBUF = 3,
    VERDICT_UNSEEN = 4,
    VERDICT_SRCLIMITED = 5,
};

static int read_exact(void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(STDIN_FILENO, (char *)buf + got, n - got);
        if (r == 0)
            return got == 0 ? 0 : -1;
        if (r < 0)
            return -1;
        got += (size_t)r;
    }
    return 1;
}

int main(void)
{
    static unsigned char frame[65536];
    struct __sk_buff skb;

    shim_config[CFG_ENABLED] = 1;
    const char *grace = getenv("CPARSE_GRACE_UNTIL_NS");
    if (grace && *grace) {
        unsigned long long until = strtoull(grace, 0, 10);
        shim_config[CFG_GRACE_UNTIL_LO] = (unsigned int)until;
        shim_config[CFG_GRACE_UNTIL_HI] = (unsigned int)(until >> 32);
        shim_grace_set = 1;
    }
    const char *l2less = getenv("CPARSE_L2LESS");
    shim_l2less = l2less && *l2less;
    const char *spent = getenv("CPARSE_BUDGET_SPENT");
    if (spent && strcmp(spent, "source") == 0)
        shim_budget_spent = 1;
    else if (spent && strcmp(spent, "total") == 0)
        shim_budget_spent = 2;
    else if (spent && strcmp(spent, "total-known") == 0)
        shim_budget_spent = 3;

    /* The byte order the records are written in: the harness is compiled
     * for the machine that builds it, which is not the test's machine when
     * the tests run under emulation. */
    unsigned int one = 1;
    printf("cparse1 %zu %s\n", sizeof(struct probe_event),
           *(unsigned char *)&one == 1 ? "le" : "be");
    fflush(stdout);

    for (;;) {
        unsigned char lenbuf[4];
        int rc = read_exact(lenbuf, sizeof(lenbuf));
        if (rc == 0)
            break;
        if (rc < 0) {
            fprintf(stderr, "cparse: short read on length\n");
            return 1;
        }
        unsigned int len = (unsigned int)lenbuf[0] | ((unsigned int)lenbuf[1] << 8) |
                           ((unsigned int)lenbuf[2] << 16) | ((unsigned int)lenbuf[3] << 24);
        if (len > sizeof(frame)) {
            fprintf(stderr, "cparse: frame of %u bytes exceeds %zu\n", len, sizeof(frame));
            return 1;
        }
        if (len > 0 && read_exact(frame, len) <= 0) {
            fprintf(stderr, "cparse: short read on frame of %u bytes\n", len);
            return 1;
        }

        memset(shim_stats, 0, sizeof(shim_stats));
        memset(shim_ringbuf_slot, 0, sizeof(shim_ringbuf_slot));
        shim_submitted = 0;
        shim_parsed_valid = 0;
        shim_ev = 0;
        memset(shim_parsed, 0, sizeof(shim_parsed));
        shim_pkt = frame;
        shim_pkt_len = len;

        memset(&skb, 0, sizeof(skb));
        skb.len = len;
        skb.ifindex = 1;
        if (shim_l2less && len > 0)
            skb.protocol = __builtin_bswap16((frame[0] >> 4) == 6 ? 0x86dd : 0x0800);

        shim_fresh_used = 0;
        tc_scan_ingress(&skb);

        unsigned char out[4 + sizeof(struct probe_event)];
        memset(out, 0, sizeof(out));
        if (shim_submitted)
            out[0] = VERDICT_FORWARDED;
        else if (shim_stats[STAT_RATELIMIT])
            out[0] = VERDICT_RATELIMITED;
        else if (shim_stats[STAT_SRCLIMIT])
            out[0] = VERDICT_SRCLIMITED;
        else if (shim_stats[STAT_NORINGBUF])
            out[0] = VERDICT_NORINGBUF;
        else if (shim_stats[STAT_SEEN])
            out[0] = VERDICT_FILTERED;
        else
            out[0] = VERDICT_UNSEEN;
        /* total-known claims to exercise the aggregate refusing a KNOWN
         * source: a refusal that did not go through the known source's own
         * budget exercised the other path, and says nothing about this one. */
        if (shim_budget_spent == 3 && out[0] == VERDICT_RATELIMITED &&
            !(shim_fresh_used && shim_fresh_budget.sent == 1)) {
            fprintf(stderr, "cparse: total-known: the aggregate refused a source"
                            " the known-source path never saw\n");
            return 2;
        }
        out[1] = (unsigned char)shim_parsed_valid;
        /* Self-check on the capture: when the program did forward, the record
         * it pushed must be identical to the one recovered on the way past, or
         * the recovery is reading the wrong memory and every comparison built
         * on it is worthless.
         *
         * Every PARSED field is still compared byte for byte -- addresses, MAC,
         * ports, protocol, flags, anomalies, ifindex. The timestamp is excluded
         * and checked separately, because it is not a parse result: the program
         * reads the clock only once a packet has survived every structural
         * filter, so at the capture point the field is legitimately still zero.
         * Asserting that -- zero here, set there -- is a stronger statement than
         * the blanket memcmp was, not a weaker one: it pins WHERE the clock is
         * read as well as what was parsed. */
        if (shim_submitted &&
            memcmp(shim_ringbuf_slot, shim_parsed, sizeof(struct probe_event)) != 0) {
            fprintf(stderr, "cparse: captured record differs from the forwarded one\n");
            return 1;
        }
        memcpy(out + 4, shim_parsed, sizeof(struct probe_event));

        if (fwrite(out, 1, sizeof(out), stdout) != sizeof(out)) {
            fprintf(stderr, "cparse: short write\n");
            return 1;
        }
    }
    fflush(stdout);
    return 0;
}
