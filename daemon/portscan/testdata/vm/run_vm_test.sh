#!/usr/bin/env bash
#
# Boots a throwaway virtual machine and runs the eBPF end-to-end test in it.
#
# Why a virtual machine: loading an eBPF program needs CAP_BPF in the initial
# user namespace. A development environment with kernel.unprivileged_bpf_disabled
# set, no capabilities and no container runtime cannot provide it, and no
# amount of unshare(1) works around it. Inside a VM we are root, so the one
# thing that could not be checked -- does the verifier accept this program, and
# does it work once attached -- can be checked.
#
# Nothing is downloaded and nothing is built as root. The hypervisor and the
# kernel are already in the Nix store, the guest runs from an initramfs built
# here, and the machine is destroyed when the test ends.
#
# Usage:
#   ./run_vm_test.sh [pcap-name]      # default: tcp-syn
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PORTSCAN_DIR="$(cd "$HERE/../.." && pwd)"
DAEMON_DIR="$(cd "$PORTSCAN_DIR/.." && pwd)"
REPO_DIR="$(cd "$DAEMON_DIR/.." && pwd)"
PCAP_NAME="${1:-tcp-syn}"

BUILD="${PORTSCAN_VM_BUILD:-$HERE/build}"

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# $BUILD/initramfs is wiped below and $BUILD can be overridden from the
# environment, so it is checked before anything is deleted. A short or relative
# path here would turn that line into an rm -rf on something that was never
# ours.
case "$BUILD" in
    /*) ;;
    *) die "PORTSCAN_VM_BUILD must be an absolute path, got '$BUILD'" ;;
esac
[ ${#BUILD} -ge 16 ] || die "refusing to build under a suspiciously short path: '$BUILD'"
mkdir -p "$BUILD"

# --- locate what we need, all of it already present ------------------------
QEMU="$(ls -d /nix/store/*qemu*/bin/qemu-system-x86_64 2>/dev/null | head -1)"
[ -n "$QEMU" ] || die "no qemu-system-x86_64 in the Nix store"

KERNEL="$(readlink -f /run/current-system/kernel 2>/dev/null || true)"
[ -f "$KERNEL" ] || KERNEL="$(ls -d /nix/store/*linux-*/bzImage 2>/dev/null | head -1)"
[ -f "$KERNEL" ] || die "no kernel bzImage in the Nix store"

BUSYBOX="$(ls -d /nix/store/*busybox*/bin/busybox 2>/dev/null | head -1)"
[ -x "$BUSYBOX" ] || die "no busybox in the Nix store"

KREL="$(basename "$(dirname "$KERNEL")" | sed 's/^[a-z0-9]*-linux-//')"
MODDIR="$(ls -d /nix/store/*-linux-"$KREL"-modules/lib/modules/"$KREL" 2>/dev/null | head -1)"
[ -d "$MODDIR" ] || die "no module tree for kernel $KREL"

say "hypervisor: $QEMU"
say "kernel:     $KERNEL ($KREL)"

# --- build the eBPF object -------------------------------------------------
CLANG="${CLANG:-$(ls -d /nix/store/*clang-wrapper*/bin/clang 2>/dev/null | head -1)}"
[ -x "$CLANG" ] || CLANG="$(command -v clang || true)"
[ -x "$CLANG" ] || die "clang is required to build the eBPF module"
LIBBPF_INCLUDE="${LIBBPF_INCLUDE:-$(ls -d /nix/store/*libbpf-*/include 2>/dev/null | head -1)}"
[ -d "$LIBBPF_INCLUDE" ] || die "libbpf headers not found; set LIBBPF_INCLUDE"

# Built through Makefile.scan, not by repeating its flags here.
#
# A private copy of the clang command line here would drift as soon as the
# Makefile changed its flags (-mcpu=v3 for the atomics in rate_limit, for
# instance): the object the VM loaded would be built differently from the one
# a distribution ships, which is the one divergence this whole end-to-end test
# exists to rule out. The Makefile is the single definition of how this object
# is compiled; TARGET redirects the output here without copying anything.
say "building the eBPF module"
make -C "$REPO_DIR/ebpf_prog" -f Makefile.scan \
    CLANG="$CLANG" LIBBPF_INCLUDE="$LIBBPF_INCLUDE" \
    TARGET="$BUILD/opensnitch-scan.o" 2>&1 \
    | grep -vE '^(Warning: supplying|clang: warning: argument unused)' || true
[ -s "$BUILD/opensnitch-scan.o" ] || die "the eBPF module did not build"

# --- build the guest test binary, statically -------------------------------
say "building the guest test binary"
( cd "$DAEMON_DIR" && CGO_ENABLED=0 GOOS=linux go build \
    -ldflags '-s -w' -o "$BUILD/vmtest" ./portscan/testdata/vm/ )
[ -s "$BUILD/vmtest" ] || die "the guest test binary did not build"

# The package's own privileged tests, compiled here because the guest has no Go
# toolchain. They exist for CI; a test written for an environment nobody has run
# it in is a test that has never run, so phase 4 runs them here too.
say "building the package's test binary"
( cd "$DAEMON_DIR" && CGO_ENABLED=0 GOOS=linux go test -c \
    -covermode=atomic -coverpkg=./portscan/ \
    -o "$BUILD/portscan.test" ./portscan/ )
[ -s "$BUILD/portscan.test" ] || die "the package test binary did not build"

# --- the capture to replay -------------------------------------------------
PCAP="$PORTSCAN_DIR/testdata/pcap/$PCAP_NAME.pcap"
[ -f "$PCAP" ] || die "capture $PCAP not found; run testdata/generate_corpus.sh first"

# --- assemble the initramfs ------------------------------------------------
say "assembling the initramfs"
ROOT="$BUILD/initramfs"
rm -rf "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,payload,lib/modules}

cp "$BUSYBOX" "$ROOT/bin/busybox"
chmod +x "$ROOT/bin/busybox"
for applet in sh mount insmod echo sleep poweroff mkdir cat ls dmesg id; do
    ln -sf busybox "$ROOT/bin/$applet"
done

# veth is a module in this kernel; TCX (CONFIG_NET_XGRESS) is built in, so no
# scheduler module is needed.
# af_packet is a module in this kernel and is what the replay writes through.
# tun provides /dev/net/tun, without which the one test covering interfaces that
# carry no link header -- the shape a VPN presents -- cannot build its device.
# nfnetlink and nf_tables are needed by phase 3, which installs real firewall
# rules. The guest loads them in that order: init_module(2) resolves no
# dependencies, and nf_tables without nfnetlink simply fails.
for mod in veth tun af_packet nfnetlink nf_tables; do
    f="$(find "$MODDIR" -name "$mod.ko*" | head -1)"
    [ -n "$f" ] || die "kernel module $mod not found under $MODDIR"
    # busybox insmod calls init_module(2), which takes no compressed
    # image, so the module is decompressed here rather than in the guest.
    case "$f" in
      *.xz)  XZ="$(ls -d /nix/store/*xz-*/bin/xz 2>/dev/null | head -1)";
             [ -x "$XZ" ] || XZ="$(command -v xz || true)";
             [ -x "$XZ" ] || die "xz is needed to decompress $f";
             "$XZ" -dc "$f" > "$ROOT/lib/modules/$mod.ko" ;;
      *.gz)  gzip -dc "$f" > "$ROOT/lib/modules/$mod.ko" ;;
      *.zst) zstd -dc "$f" > "$ROOT/lib/modules/$mod.ko" ;;
      *)     cp "$f" "$ROOT/lib/modules/$mod.ko" ;;
    esac
    [ -s "$ROOT/lib/modules/$mod.ko" ] || die "module $mod is empty after decompression"
done

cp "$BUILD/opensnitch-scan.o" "$ROOT/payload/"
cp "$PCAP" "$ROOT/payload/$PCAP_NAME.pcap"
cp "$BUILD/vmtest" "$ROOT/bin/vmtest"
cp "$BUILD/portscan.test" "$ROOT/bin/portscan.test"


CPIO="$(ls -d /nix/store/*cpio-*/bin/cpio 2>/dev/null | head -1)"
[ -x "$CPIO" ] || CPIO="$(command -v cpio || true)"
[ -x "$CPIO" ] || die "cpio is required to build the initramfs (busybox here has no cpio applet)"
# Everything in the guest belongs to root, as it does on a real installation.
#
# Without -R the archive carries the build user's uid, so /payload arrived owned
# by uid 1000 and the daemon refused to load an eBPF object from a directory it
# does not trust -- correctly. A guest whose filesystem is owned by an ordinary
# user is not the system this test is meant to stand in for.
( cd "$ROOT" && find . -print0 | "$CPIO" --null -o -H newc -R 0:0 --quiet ) > "$BUILD/initramfs.cpio"
[ -s "$BUILD/initramfs.cpio" ] || die "the initramfs is empty"
say "initramfs: $(du -h "$BUILD/initramfs.cpio" | cut -f1)"

# --- boot ------------------------------------------------------------------
say "booting the guest (KVM accelerated)"
LOG="$BUILD/console.log"
set +e
timeout 180 "$QEMU" \
    -M microvm,acpi=off \
    -enable-kvm -cpu host -smp 2 -m 1024 \
    -nographic -no-reboot \
    -kernel "$KERNEL" \
    -initrd "$BUILD/initramfs.cpio" \
    -append "console=ttyS0 panic=1 loglevel=4 rdinit=/bin/vmtest PORTSCAN_MODULE_DIR=/payload PORTSCAN_PCAP=/payload/$PCAP_NAME.pcap" \
    > "$LOG" 2>&1
set -e

echo
# -a because the serial console log contains the kernel's own binary noise,
# which makes grep treat the whole file as binary and print nothing. The awk
# drops the duplicate every line gets from the console being echoed back.
grep -a 'VMTEST-' "$LOG" | tr -d '\r' | grep -v 'VMTEST-COVER-' | awk '!seen[$0]++' || true
echo

# The guest has no writable storage the harness can read, so phase 4 prints its
# coverage profile to the console between markers. Recovering it here is what
# lets source_ebpf.go -- the one file that runs nowhere else -- appear in a
# merged coverage figure instead of as a blank.
COVER="$BUILD/cover-vm.out"
if grep -aq 'VMTEST-COVER-BEGIN' "$LOG"; then
    sed -n '/VMTEST-COVER-BEGIN/,/VMTEST-COVER-END/p' "$LOG" \
        | tr -d '\r' \
        | grep -av 'VMTEST-COVER-' > "$COVER"
    if [ -s "$COVER" ]; then
        say "coverage profile from the guest: $COVER ($(wc -l < "$COVER") blocks)"
    fi
fi

if grep -aq 'VMTEST-RESULT: PASS' "$LOG"; then
    say "PASS - kernel half, cost measurement and production chain all green"
    exit 0
fi
if grep -aq 'VMTEST-RESULT: FAIL' "$LOG"; then
    die "the guest test failed; full console in $LOG"
fi
echo "--- last 30 console lines ---"
tail -30 "$LOG"
die "the guest produced no verdict; full console in $LOG"
