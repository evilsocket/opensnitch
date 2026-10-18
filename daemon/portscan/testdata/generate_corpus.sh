#!/usr/bin/env bash
#
# Generates the differential-test corpus: real scan traffic, produced by real
# nmap, captured on the victim's interface.
#
# The point of this harness is that the expected verdict is derived from the
# nmap option used, which is ground truth independent of the detection code.
# Expectation-based tests written by hand share whatever misconception shaped
# the implementation; running the actual tool does not.
#
# Topology: two network namespaces joined by a veth pair.
#
#     netns A (victim)                    netns B (attacker)
#     veth0  10.77.0.1/24  <---------->   veth1  10.77.0.2/24
#            fd00:77::1/64                       fd00:77::2/64
#
# tcpdump captures on veth0 inside A while nmap runs inside B, so the recorded
# frames are exactly what a TC ingress hook on the victim would see, including
# the Ethernet header.
#
# Requires no privileges beyond an unprivileged user namespace:
#   unshare -Urn gives CAP_NET_ADMIN and CAP_NET_RAW inside the new namespaces.
#
# Usage:  ./generate_corpus.sh [output-dir]
#
set -euo pipefail

OUTDIR="${1:-$(cd "$(dirname "$0")" && pwd)/pcap}"

if [ "${INSIDE_NETNS:-}" != "1" ]; then
    command -v nmap    >/dev/null || { echo "nmap is required"    >&2; exit 1; }
    command -v tcpdump >/dev/null || { echo "tcpdump is required" >&2; exit 1; }
    command -v unshare >/dev/null || { echo "unshare is required" >&2; exit 1; }
    mkdir -p "$OUTDIR"
    exec unshare -Urn --fork env INSIDE_NETNS=1 "$0" "$OUTDIR"
fi

VICTIM4=10.77.0.1
ATTACK4=10.77.0.2
VICTIM6=fd00:77::1
ATTACK6=fd00:77::2

cleanup() {
    [ -n "${PEER:-}" ] && kill "$PEER" 2>/dev/null || true
    [ -n "${LOGDIR:-}" ] && rm -rf "$LOGDIR" || true
}
trap cleanup EXIT

# --- build the topology --------------------------------------------------
ip link add veth0 type veth peer name veth1
unshare -n sleep 3600 &
PEER=$!
sleep 0.3
ip link set veth1 netns "$PEER"

ip addr add "$VICTIM4/24" dev veth0
ip -6 addr add "$VICTIM6/64" dev veth0 nodad
ip link set lo up
ip link set veth0 up

nsenter -t "$PEER" -n ip addr add "$ATTACK4/24" dev veth1
nsenter -t "$PEER" -n ip -6 addr add "$ATTACK6/64" dev veth1 nodad
nsenter -t "$PEER" -n ip link set lo up
nsenter -t "$PEER" -n ip link set veth1 up
sleep 0.5

# tcpdump's stderr goes here rather than next to the captures, so that a
# capture that fails can say why.
LOGDIR=$(mktemp -d)

# Debian and Ubuntu build tcpdump to switch to a dedicated "tcpdump" user once
# the capture is open. Only uid 0 is mapped in this user namespace, so that
# switch fails and tcpdump exits before capturing anything. "-Z root" keeps it
# as it is on those builds, but a build without a default user takes "-Z root"
# as a request to switch to root, through initgroups(), which the namespace
# refuses. Whichever form stays up is the one this tcpdump accepts.
TCPDUMP_OPTS=()
for opts in "" "-Z root"; do
    # shellcheck disable=SC2086
    tcpdump $opts -i lo -w "$LOGDIR/probe.pcap" -n >"$LOGDIR/probe.log" 2>&1 &
    td=$!
    sleep 0.6
    if kill -0 "$td" 2>/dev/null; then
        kill -INT "$td" 2>/dev/null || true
        wait "$td" 2>/dev/null || true
        # shellcheck disable=SC2206
        TCPDUMP_OPTS=($opts)
        break
    fi
    wait "$td" 2>/dev/null || true
    if [ -n "$opts" ]; then
        echo "tcpdump cannot capture in this user namespace:" >&2
        cat "$LOGDIR/probe.log" >&2
        exit 1
    fi
done

# --- capture one scan ----------------------------------------------------
# capture <name> <nmap args...>
capture() {
    local name="$1"; shift
    local pcap="$OUTDIR/$name.pcap"
    local log="$LOGDIR/$name.log"

    # --immediate-mode: otherwise libpcap hands packets over a buffer at a
    # time, and the SIGINT below can drop the last buffer, or the whole of a
    # short scan, unread.
    tcpdump "${TCPDUMP_OPTS[@]}" -i veth0 -w "$pcap" -U --immediate-mode \
        -s 256 -n 'not arp' >"$log" 2>&1 &
    local td=$!
    sleep 0.6
    if ! kill -0 "$td" 2>/dev/null; then
        echo "tcpdump exited before the $name scan:" >&2
        cat "$log" >&2
        exit 1
    fi

    nsenter -t "$PEER" -n nmap "$@" >/dev/null 2>&1 || true

    sleep 0.6
    kill -INT "$td" 2>/dev/null || true
    wait "$td" 2>/dev/null || true

    # Every scan, the benign one included, sends something: an empty capture
    # means the harness failed, and the tests would then have nothing to check.
    local n
    n=$(tcpdump -r "$pcap" 2>/dev/null | wc -l || echo 0)
    printf '  %-28s %6s packets\n' "$name" "$n"
    if [ "$n" -eq 0 ]; then
        echo "empty capture for $name:" >&2
        cat "$log" >&2
        exit 1
    fi
}

echo "Generating scan corpus into $OUTDIR"

# --- TCP techniques, IPv4 -------------------------------------------------
capture tcp-syn            -sS -p 1-120 -n --max-retries 0 -T4  "$VICTIM4"
capture tcp-connect        -sT -p 1-120 -n --max-retries 0 -T4  "$VICTIM4"
capture tcp-fin            -sF -p 1-120 -n --max-retries 0 -T4  "$VICTIM4"
capture tcp-null           -sN -p 1-120 -n --max-retries 0 -T4  "$VICTIM4"
capture tcp-xmas           -sX -p 1-120 -n --max-retries 0 -T4  "$VICTIM4"
capture tcp-ack            -sA -p 1-120 -n --max-retries 0 -T4  "$VICTIM4"
capture tcp-window         -sW -p 1-120 -n --max-retries 0 -T4  "$VICTIM4"
capture tcp-maimon         -sM -p 1-120 -n --max-retries 0 -T4  "$VICTIM4"
capture tcp-custom-flags   -sS --scanflags PSHURG -p 1-120 -n --max-retries 0 -T4 "$VICTIM4"
capture tcp-synfin         -sS --scanflags SYNFIN -p 1-120 -n --max-retries 0 -T4 "$VICTIM4"

# --- UDP and IP protocol --------------------------------------------------
# UDP probes are worth one point each, so a wider range is needed to cross the
# threshold; ICMP rate limiting makes this the slowest capture.
capture udp                -sU -p 1-400 -n --max-retries 0 -T4  "$VICTIM4"
capture ip-protocol        -sO -n --max-retries 0 -T4           "$VICTIM4"

# --- IPv6 -----------------------------------------------------------------
capture tcp-syn-v6         -6 -sS -p 1-120 -n --max-retries 0 -T4 "$VICTIM6"
capture tcp-fin-v6         -6 -sF -p 1-120 -n --max-retries 0 -T4 "$VICTIM6"
capture tcp-xmas-v6        -6 -sX -p 1-120 -n --max-retries 0 -T4 "$VICTIM6"
capture udp-v6             -6 -sU -p 1-400 -n --max-retries 0 -T4 "$VICTIM6"

# --- evasion --------------------------------------------------------------
capture tcp-syn-fragmented -sS -f -p 1-120 -n --max-retries 0 -T4 "$VICTIM4"
capture tcp-syn-decoy      -sS -D 10.77.0.50,10.77.0.51,ME -p 1-120 -n --max-retries 0 -T4 "$VICTIM4"
capture tcp-syn-slow       -sS -p 1-40 -n --max-retries 0 -T1 "$VICTIM4"
capture tcp-os-fingerprint -sS -O --osscan-limit -p 1-40 -n --max-retries 0 -T4 "$VICTIM4"

# --- benign traffic, which must NOT be reported ---------------------------
# A single connection attempt to one closed port, retried. This is the shape of
# an ordinary application failing to reach a stopped service.
capture benign-single-port -sS -p 22 -n --max-retries 6 -T4 "$VICTIM4"

echo "done."
