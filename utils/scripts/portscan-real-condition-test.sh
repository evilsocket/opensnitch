#!/usr/bin/env bash
#
# Checks inbound port scan detection on this machine, with real nmap scans,
# without sending anything on the local network.
#
# A network namespace (the "scanner") is joined to this machine by a veth
# pair. The target address goes on the host side of the pair; the nmap
# commands of the project's capture corpus, plus --spoof-mac and an IPv6
# benign control, are run from the scanner, and the daemon's log is read after
# each scan to compare what it reported with what the wiki page
# Port-Scan-Detection-Coverage expects. Everything is removed at the end, on
# Ctrl-C or on an error.
#
# Each test starts from a new source address and MAC address: the daemon
# reports a source again only after ReportCooldown (5 minutes), and with one
# source most tests would go unreported. These addresses exist only on this
# machine: blocking them cuts nothing off.
#
# Usage: sudo ./portscan-real-condition-test.sh [options] <IPv4 target>
#   The target must be private (10/8, 172.16/12, 192.168/16), and its /24
#   (and fd5c:a11e:7e57::/64 for the IPv6 tests) a network nothing on this
#   machine routes to: the script checks the routes, then asks the kernel
#   where the replies would go, and refuses otherwise. Example: 10.99.0.1
#
# Options:
#   -m, --mode MODE        full (default): every test, IPv4 and IPv6
#                          ipv4: the IPv4 tests only; ipv6: the IPv6 tests only
#                          quick: the main techniques, IPv4 and IPv6, a few minutes
#   -i, --interface NAME   name of the host side of the veth pair (at most 13
#                          characters); by default a new name each run, psdNNNN
#   -t, --interval SECONDS time between two tests: 180 by default, 30 in quick
#   -l, --log FILE         the daemon's log; by default the most recently
#                          written of /var/log/opensnitchd.log and
#                          /var/log/opensnitchd-dev.log
#   -h, --help
#
# Requires root, ip (iproute2), nmap, and the daemon running with port scan
# detection on every interface ("Interfaces": [] in its PortScan section, the
# default).
set -euo pipefail

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { sed -n '3,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit "${1:-0}"; }

# ---------------------------------------------------------------- arguments
MODE=full
VH=""
INTERVAL=""
LOG=""
TARGET=""
while [ $# -gt 0 ]; do
    case "$1" in
        -m|--mode)      [ $# -ge 2 ] || die "$1 needs a value"; MODE=$2; shift 2 ;;
        -i|--interface) [ $# -ge 2 ] || die "$1 needs a value"; VH=$2; shift 2 ;;
        -t|--interval)  [ $# -ge 2 ] || die "$1 needs a value"; INTERVAL=$2; shift 2 ;;
        -l|--log)       [ $# -ge 2 ] || die "$1 needs a value"; LOG=$2; shift 2 ;;
        -h|--help)      usage 0 ;;
        -*)             die "unknown option $1 (see --help)" ;;
        *)              [ -z "$TARGET" ] || die "one target only (see --help)"; TARGET=$1; shift ;;
    esac
done
[ -n "$TARGET" ] || usage 1
case "$MODE" in
    full|ipv4|ipv6|quick) ;;
    *) die "unknown mode '$MODE': full, ipv4, ipv6 or quick" ;;
esac
if [ -z "$INTERVAL" ]; then
    if [ "$MODE" = quick ]; then INTERVAL=30; else INTERVAL=180; fi
fi
[[ $INTERVAL =~ ^[0-9]+$ ]] || die "the interval is a number of seconds"
if [ -z "$VH" ]; then
    VH=psd$(printf '%04x' $((RANDOM % 65536)))
fi
# Interface names hold 15 characters; the peer adds "-p" and the namespace "-ns".
[[ $VH =~ ^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,12}$ ]] \
    || die "'$VH' is not a usable interface name (letters, digits, '.', '_', '-', at most 13)"
VS=$VH-p                 # scanner side of the pair
NS=$VH-ns                # the scanner's namespace
NET6=fd5c:a11e:7e57      # ULA prefix of the pair, for the IPv6 tests

# ------------------------------------------------------------------- checks
[ "$(id -u)" -eq 0 ] || die "run it with sudo: it creates a network namespace and a veth pair"
command -v ip   >/dev/null || die "ip (iproute2) not found"
command -v nmap >/dev/null || die "nmap not found"

# No leading zero: iproute2 reads 010 as octal, and 010.99.0.1 would put the
# public 8.99.0.1 on this machine.
OCTET='(0|[1-9][0-9]{0,2})'
[[ $TARGET =~ ^$OCTET\.$OCTET\.$OCTET\.$OCTET$ ]] \
    || die "$TARGET is not an IPv4 address in dotted decimal, without leading zeros"
A=${BASH_REMATCH[1]}; B=${BASH_REMATCH[2]}; C=${BASH_REMATCH[3]}; D=${BASH_REMATCH[4]}
for o in "$A" "$B" "$C" "$D"; do
    [ "$o" -le 255 ] || die "$TARGET is not an IPv4 address"
done
[ "$D" -ge 1 ] && [ "$D" -le 254 ] || die "the last byte must be between 1 and 254"
if ! { [ "$A" -eq 10 ] || { [ "$A" -eq 172 ] && [ "$B" -ge 16 ] && [ "$B" -le 31 ]; } \
       || { [ "$A" -eq 192 ] && [ "$B" -eq 168 ]; }; }; then
    die "$TARGET is not a private address: pick one in 10/8, 172.16/12 or 192.168/16"
fi
PREFIX=$A.$B.$C

# The routes of this machine, in any table, that overlap the /24 (or the IPv6
# prefix of the tests), one per line:
# - any route inside it (a smaller network on a real interface, a local
#   address): its hosts would be answered, and blocked;
# - a route containing it, /8 or narrower (a VPN's 10.0.0.0/8, a static route
#   to it): blocking the test's sources would block real hosts there.
# Wider ones are left (a default route, OpenVPN's 0.0.0.0/1 halves,
# fc00::/7): they cover whole address ranges, not a network, and the /24's
# own route is more specific. Where the replies really go, routing rules
# included, is checked once the pair is up (check_path).
overlapping() {   # overlapping <-4|-6> <prefix>
    local fam=$1 pfx=$2 line t1 t2 dst len
    {
        ip -o "$fam" route show table all root "$pfx" 2>/dev/null || true
        ip -o "$fam" route show table all match "$pfx" 2>/dev/null | while read -r line; do
            read -r t1 t2 _ <<<"$line"
            dst=$t1
            case "$t1" in
                unicast|unreachable|blackhole|prohibit|throw|local|broadcast|anycast|multicast|nat) dst=$t2 ;;
            esac
            [ "$dst" != default ] || continue
            len=${dst##*/}
            if [ "$len" = "$dst" ]; then
                if [ "$fam" = -4 ]; then len=32; else len=128; fi
            fi
            if [ "$len" -ge 8 ]; then echo "$line"; fi
        done
    } | sort -u
}
routes=$(overlapping -4 "$PREFIX.0/24")
if [ -n "$routes" ]; then
    die "$PREFIX.0/24 overlaps a route of this machine; pick a /24 that nothing here uses:
$routes"
fi
if ip netns list 2>/dev/null | grep -qw "$NS"; then
    die "a namespace named $NS already exists: pick another name with -i"
fi
for name in "$VH" "$VS"; do
    if ip link show "$name" >/dev/null 2>&1; then
        die "an interface named $name already exists: pick another name with -i"
    fi
done

V6=1
if [ "$MODE" = ipv4 ]; then
    V6=0
elif [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = 1 ]; then
    V6=0
    [ "$MODE" != ipv6 ] || die "IPv6 is disabled on this machine"
    warn "IPv6 is disabled on this machine: the IPv6 tests are skipped"
else
    routes=$(overlapping -6 "$NET6::/64")
    if [ -n "$routes" ]; then
        die "$NET6::/64, the prefix of the IPv6 tests, overlaps a route of this machine (use -m ipv4):
$routes"
    fi
fi

if [ -z "$LOG" ]; then
    LOG=$(ls -t /var/log/opensnitchd.log /var/log/opensnitchd-dev.log 2>/dev/null | head -1 || true)
fi
if [ -z "$LOG" ] || [ ! -f "$LOG" ]; then
    warn "the daemon's log was not found (--log): the results will not be read"
    LOG=
fi

# Scanner addresses: one per test, from .101 on, never the target.
host_part() {   # host_part <n>: the n-th free address from .101
    local h=$((100 + $1))
    if [ "$D" -gt 100 ] && [ "$h" -ge "$D" ]; then h=$((h + 1)); fi
    echo "$h"
}
DECOYS=()
for h in 50 51 52; do
    if [ "$h" -ne "$D" ]; then DECOYS+=("$PREFIX.$h"); fi
done
DECOY_LIST="${DECOYS[0]},${DECOYS[1]},ME"
TARGET6=$NET6::1

# ---------------------------------------------------------------- teardown
# Nothing may stop the teardown, writing included: with "| tee" and Ctrl-C the
# reader of stdout is gone (SIGPIPE), and with a closed terminal writes fail
# (EIO). So it ignores those, removes first, and says so after, if it can.
cleanup() {
    set +e
    trap '' PIPE HUP INT TERM
    trap - EXIT
    # The scan or the pause running now, so that a signal acts at once.
    local pids
    pids=$(jobs -p)
    if [ -n "$pids" ]; then kill $pids 2>/dev/null; fi
    ip netns del "$NS" 2>/dev/null
    ip link del "$VH" 2>/dev/null      # gone with the namespace, in case
    if [ -n "${RULE4:-}" ]; then ip -4 rule del $RULE4 2>/dev/null; fi
    if [ -n "${RULE6:-}" ]; then ip -6 rule del $RULE6 2>/dev/null; fi
    rm -f "$NMAP_OUT"
    say "removed the namespace $NS and the veth pair $VH" 2>/dev/null
}
NMAP_OUT=$(mktemp)
trap cleanup EXIT
trap 'trap "" PIPE; warn "interrupted" || true; exit 130' INT TERM HUP

# Waits run in the background and are waited for, so that a signal is
# handled at once instead of after a 3-minute pause or a 10-minute scan.
pause() { sleep "$1" & wait $!; }

# The replies must stay on the pair whatever the routing rules say: a rule
# before the main table that sends everything to a table with its own default
# route (a multi-WAN setup, a VPN exit node) would carry them to a real
# network, and no route listing shows it. Asked of the kernel once the pair
# is up, before any packet is sent from it.
check_path() {   # check_path <-4|-6> <destination> <source>
    local out
    out=$(ip "$1" route get "$2" from "$3" 2>&1 | head -1)
    case " $out " in
        *" dev $VH "*) return 0 ;;
    esac
    die "the replies to $2 would not stay on $VH, so they could reach a real network:
  $out
the routing rules of this machine:
$(ip "$1" rule show 2>&1)"
}

# ------------------------------------------------------------------- set up
# The log's size is taken before the interface exists: a "watching" line
# written while it is being set up must not be missed.
# The last bytes before it identify the log: a rotation (a new file) or a
# truncation (logrotate's copytruncate) changes them, even once the new log
# has outgrown the old one.
log_mark() { tail -c +$(($1 > 64 ? $1 - 63 : 1)) "$LOG" 2>/dev/null | head -c "$(($1 > 64 ? 64 : $1))" | od -An -tx1 | tr -d ' \n'; }
if [ -n "$LOG" ]; then
    start=$(stat -c %s "$LOG")
    mark=$(log_mark "$start")
fi
say "setting up: target $TARGET on $VH, scanner in the namespace $NS"
ip netns add "$NS"
ip link add "$VH" type veth peer name "$VS"
ip link set "$VS" netns "$NS"
ip addr add "$TARGET/24" dev "$VH"
if [ "$V6" = 1 ]; then
    # Only for the two ends of the pair: a machine whose new interfaces start
    # with IPv6 off (conf.default.disable_ipv6) would refuse the addresses.
    echo 0 > "/proc/sys/net/ipv6/conf/$VH/disable_ipv6"
    ip netns exec "$NS" sh -c "echo 0 > /proc/sys/net/ipv6/conf/$VS/disable_ipv6"
    ip -6 addr add "$TARGET6/64" dev "$VH" nodad
fi
ip link set "$VH" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$VS" up
# For the whole run, the test's networks are looked up in the main table,
# where the pair's routes are, before any other routing rule: a rule on a
# port, a protocol or a firewall mark, which a route lookup cannot
# reproduce, or one a VPN adds while the tests run, cannot then take the
# replies elsewhere. Removed by the teardown.
# Recorded only once added: the teardown must not delete a rule of the
# user's that happens to read the same.
spec="pref 1 to $PREFIX.0/24 lookup main"
ip -4 rule add $spec
RULE4=$spec
if [ "$V6" = 1 ]; then
    spec="pref 1 to $NET6::/64 lookup main"
    ip -6 rule add $spec
    RULE6=$spec
fi
check_path -4 "$PREFIX.$(host_part 1)" "$TARGET"
check_path -4 "${DECOYS[0]}" "$TARGET"
if [ "$V6" = 1 ]; then check_path -6 "$NET6::$(printf '%x' "$(host_part 1)")" "$TARGET6"; fi

# The daemon looks at its interfaces again every minute, and logs "now also
# watching <interface>": wait for it, 2 minutes at most. Without it, nothing
# that follows could be detected.
if [ -n "$LOG" ]; then
    say "waiting for the daemon to watch $VH (2 minutes at most)"
    waited=0
    until tail -c +$((start + 1)) "$LOG" | grep -q "watching.*$VH"; do
        # Rotated or truncated meanwhile: read the new content from its start.
        if [ "$start" -gt 0 ] && [ "$(log_mark "$start")" != "$mark" ]; then start=0; fi
        pause 5; waited=$((waited + 5))
        if [ "$waited" -ge 120 ]; then
            die "the daemon did not say it watches $VH within 2 minutes, in $LOG. Check that the daemon runs, that port scan detection is on (\"Enabled\": true in its PortScan section; it is off by default), and that \"Interfaces\" there is empty."
        fi
    done
else
    say "waiting 75 s for the daemon to see $VH"
    pause 75
fi

# -------------------------------------------------------------------- tests
# name | expected result (the method in the daemon's log, or "none") |
# family (4 or 6) | in quick mode (q) | nmap options. The commands of the
# project's capture corpus (daemon/portscan/testdata/generate_corpus.sh),
# plus --spoof-mac and the IPv6 benign control; the expected results are
# those of the wiki page Port-Scan-Detection-Coverage.
ALL_TESTS=(
"tcp-syn|tcp-syn|4|q|-sS -p 1-120 -n --max-retries 0 -T4"
"tcp-connect|tcp-syn|4|q|-sT -p 1-120 -n --max-retries 0 -T4"
"tcp-fin|tcp-fin|4|-|-sF -p 1-120 -n --max-retries 0 -T4"
"tcp-null|tcp-null|4|-|-sN -p 1-120 -n --max-retries 0 -T4"
"tcp-xmas|tcp-xmas|4|q|-sX -p 1-120 -n --max-retries 0 -T4"
"tcp-maimon|tcp-maimon|4|-|-sM -p 1-120 -n --max-retries 0 -T4"
"tcp-ack|tcp-ack|4|-|-sA -p 1-120 -n --max-retries 0 -T4"
"tcp-window|tcp-ack|4|-|-sW -p 1-120 -n --max-retries 0 -T4"
"tcp-custom-flags|tcp-custom-flags|4|-|-sS --scanflags PSHURG -p 1-120 -n --max-retries 0 -T4"
"tcp-synfin|tcp-syn-fin|4|-|-sS --scanflags SYNFIN -p 1-120 -n --max-retries 0 -T4"
"udp|udp|4|q|-sU -p 1-400 -n --max-retries 0 -T4"
"ip-protocol|ip-protocol|4|-|-sO -n --max-retries 0 -T4"
"tcp-syn-fragmented|tcp-fragmented|4|-|-sS -f -p 1-120 -n --max-retries 0 -T4"
"tcp-syn-decoy|tcp-syn|4|-|-sS -D $DECOY_LIST -p 1-120 -n --max-retries 0 -T4"
"tcp-os-fingerprint|tcp-syn|4|-|-sS -O --osscan-limit -p 1-40 -n --max-retries 0 -T4"
"tcp-syn-spoof-mac|tcp-syn|4|-|-sS --spoof-mac Dell -p 1-120 -n --max-retries 0 -T4"
"tcp-syn-v6|tcp-syn|6|q|-6 -sS -p 1-120 -n --max-retries 0 -T4"
"tcp-fin-v6|tcp-fin|6|-|-6 -sF -p 1-120 -n --max-retries 0 -T4"
"tcp-xmas-v6|tcp-xmas|6|q|-6 -sX -p 1-120 -n --max-retries 0 -T4"
"udp-v6|udp|6|-|-6 -sU -p 1-400 -n --max-retries 0 -T4"
"tcp-syn-slow|tcp-syn|4|-|-sS -p 1-40 -n --max-retries 0 -T1"
"benign-single-port|none|4|q|-sS -p 22 -n --max-retries 6 -T4"
"benign-single-port-v6|none|6|-|-6 -sS -p 22 -n --max-retries 6 -T4"
)
TESTS=()
for t in "${ALL_TESTS[@]}"; do
    IFS='|' read -r _n _e fam quick _o <<<"$t"
    case "$MODE" in
        full)  TESTS+=("$t") ;;
        ipv4)  if [ "$fam" = 4 ]; then TESTS+=("$t"); fi ;;
        ipv6)  if [ "$fam" = 6 ]; then TESTS+=("$t"); fi ;;
        quick) if [ "$quick" = q ]; then TESTS+=("$t"); fi ;;
    esac
done
TOTAL=${#TESTS[@]}
slow=0
for t in "${TESTS[@]}"; do
    case "$t" in tcp-syn-slow*) slow=10 ;; esac
done
say "mode $MODE: $TOTAL tests, $INTERVAL s apart, about $(( (TOTAL - 1) * INTERVAL / 60 + 2 + slow )) minutes"

SUMMARY=()
i=0
for t in "${TESTS[@]}"; do
    i=$((i + 1))
    IFS='|' read -r name expect fam _quick opts <<<"$t"
    h=$(host_part "$i")
    src=$PREFIX.$h
    src6=$NET6::$(printf '%x' "$h")
    mac=$(printf '02:00:00:00:99:%02x' "$i")

    if [ "$fam" = 6 ] && [ "$V6" = 0 ]; then
        SUMMARY+=("$(printf '%-22s %-16s %s' "$name" "$expect" "skipped (IPv6 disabled)")")
        continue
    fi

    # A new source address and MAC address for this test.
    ip netns exec "$NS" ip addr flush dev "$VS"
    ip netns exec "$NS" ip link set dev "$VS" down
    ip netns exec "$NS" ip link set dev "$VS" address "$mac"
    ip netns exec "$NS" ip link set dev "$VS" up
    ip netns exec "$NS" ip addr add "$src/24" dev "$VS"
    if [ "$V6" = 1 ]; then ip netns exec "$NS" ip -6 addr add "$src6/64" dev "$VS" nodad; fi

    if [ "$fam" = 6 ]; then dst=$TARGET6; from=$src6; else dst=$TARGET; from=$src; fi
    echo
    say "[$i/$TOTAL] $name  (source $from, MAC $mac, expected: $expect)"
    echo "    nmap $opts $dst"
    off=0
    if [ -n "$LOG" ]; then off=$(stat -c %s "$LOG"); fi
    # shellcheck disable=SC2086
    ip netns exec "$NS" nmap $opts "$dst" > "$NMAP_OUT" 2>&1 &
    wait $! || true
    grep -E 'Nmap done|Not shown|ports? (on|scanned)|WARNING|QUITTING' "$NMAP_OUT" \
        | sed 's/^/    nmap: /' || true
    pause 5   # time for the report to go out and be logged

    if [ -n "$LOG" ]; then
        sources="$from"
        if [ "$name" = tcp-syn-decoy ]; then sources="$from|${DECOYS[0]}|${DECOYS[1]}"; fi
        seen=$(tail -c +$((off + 1)) "$LOG" | grep -F '[port scan]' | grep -E " from ($sources) " || true)
        if [ -n "$seen" ]; then
            echo "$seen" | sed 's/^/    daemon: /'
            if [ "$expect" = none ]; then verdict="REPORTED, and nothing was expected"
            elif echo "$seen" | grep -q " $expect from "; then verdict="reported as expected"
            else verdict="reported, under another name"
            fi
        elif [ "$expect" = none ]; then
            verdict="nothing reported, as expected"
        else
            verdict="nothing in the log (a report delayed by the alert limiter can come later)"
        fi
    else
        verdict="not read (no log)"
    fi
    echo "    => $verdict"
    SUMMARY+=("$(printf '%-22s %-16s %s' "$name" "$expect" "$verdict")")

    if [ "$i" -lt "$TOTAL" ]; then say "waiting $INTERVAL s"; pause "$INTERVAL"; fi
done

echo
say "summary"
printf '%-22s %-16s %s\n' "test" "expected" "result"
printf '%s\n' "${SUMMARY[@]}"
echo
echo "The sources from $PREFIX.101 on that the daemon blocked stay in the Port scan"
echo "Detection tab until they expire; they exist only on this machine, so"
echo "releasing or deleting them is optional."
