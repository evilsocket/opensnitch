#!/usr/bin/env bash
#
# Merges the coverage of every environment this package is tested in.
#
# No single run can cover it: the packet sources and the firewall backend need
# capabilities that a plain `go test` does not have, and each lives in its own
# isolated environment. Reporting only the unprivileged run would understate the
# coverage; reporting each separately would never add up.
#
#   plain              the pure logic, in this shell
#   user namespace     AF_PACKET, with a real nmap scan
#   user namespace     nftables, installing and removing real rules
#   virtual machine    the eBPF program, loaded and attached for real
#
# The virtual machine has no writable storage to hand a profile back through, so
# its profile comes out over the serial console; run_vm_test.sh recovers it.
#
# Usage:
#   ./testdata/coverage_all.sh            merge whatever is available
#   ./testdata/coverage_all.sh --run-vm   boot the VM first (slow)
set -euo pipefail

cd "$(dirname "$0")/.."
PKG_DIR="$PWD"
DAEMON_DIR="$(cd .. && pwd)"
OUT="${PORTSCAN_COVER_DIR:-$PKG_DIR/testdata/.cover}"

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# $OUT is wiped below and can be overridden from the environment, so it is
# checked first. An empty, short or relative path here would turn this line into
# an rm -rf on something that was never ours.
case "$OUT" in
    /*) ;;
    *) die "PORTSCAN_COVER_DIR must be an absolute path, got '$OUT'" ;;
esac
[ ${#OUT} -ge 16 ] || die "refusing to wipe a suspiciously short path: '$OUT'"
[ ! -e "$OUT" ] || [ -d "$OUT" ] || die "$OUT exists and is not a directory"

rm -rf "$OUT"
mkdir -p "$OUT"/{plain,live,nft}

say "building the test binary with coverage instrumentation"
( cd "$DAEMON_DIR" && go test -covermode=atomic -coverpkg=./portscan/ \
    -c -o "$OUT/portscan.test" ./portscan/ )

say "plain run"
"$OUT/portscan.test" -test.gocoverdir="$OUT/plain" > "$OUT/plain.log" 2>&1 \
    || die "the plain run failed; see $OUT/plain.log"

say "AF_PACKET, in a user namespace, with a real scan"
unshare -Urn --fork env PORTSCAN_REQUIRE_LIVE=1 \
    "$OUT/portscan.test" -test.run TestLiveAFPacket -test.gocoverdir="$OUT/live" \
    > "$OUT/live.log" 2>&1 || die "the live run failed; see $OUT/live.log"

say "nftables, in a user namespace, with real rules"
unshare -Urn --fork env PORTSCAN_REQUIRE_NFT=1 \
    "$OUT/portscan.test" -test.run TestNftBlocker -test.gocoverdir="$OUT/nft" \
    > "$OUT/nft.log" 2>&1 || die "the nftables run failed; see $OUT/nft.log"

VM_PROFILE="$PKG_DIR/testdata/vm/build/cover-vm.out"
if [ "${1:-}" = "--run-vm" ]; then
    say "eBPF, in a virtual machine"
    ./testdata/vm/run_vm_test.sh < /dev/null > "$OUT/vm.log" 2>&1 \
        || die "the VM run failed; see $OUT/vm.log"
fi

say "merging"
( cd "$DAEMON_DIR" && go tool covdata textfmt \
    -i="$OUT/plain,$OUT/live,$OUT/nft" -o "$OUT/local.out" )

# covermode=atomic counts are additive, so merging two text profiles is a sum
# per block. The VM profile arrives as text because the guest cannot write a
# coverage directory the harness could read.
if [ -s "$VM_PROFILE" ]; then
    awk '
      FNR==1 && /^mode:/ { mode=$2; next }
      { key=$1" "$2
        cnt[key]+=$3
        if (!(key in seen)) { seen[key]=1; order[++n]=key } }
      END { print "mode: " mode
            for (i=1; i<=n; i++) { split(order[i], a, " "); print a[1], a[2], cnt[order[i]] } }
    ' "$OUT/local.out" "$VM_PROFILE" > "$OUT/all.out"
    say "included the profile from the virtual machine"
else
    cp "$OUT/local.out" "$OUT/all.out"
    say "no VM profile at $VM_PROFILE; source_ebpf.go will look untested"
    say "run with --run-vm, or run testdata/vm/run_vm_test.sh first"
fi

echo
( cd "$DAEMON_DIR" && go tool cover -func="$OUT/all.out" ) \
    | sed 's|.*portscan/||' \
    | awk -F'[:\t ]+' '
        $1!="total" { f=$1; p=$NF; gsub("%","",p); s[f]+=p; n[f]++ }
        END { for (x in s) printf "%-26s %5.1f%%\n", x, s[x]/n[x] }' \
    | sort -k2 -rn
echo
( cd "$DAEMON_DIR" && go tool cover -func="$OUT/all.out" | tail -1 )
echo
say "profile: $OUT/all.out"
