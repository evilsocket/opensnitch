#!/usr/bin/env bash
#
# Cross-checks the three implementations of the port scan alert: the Go
# bindings the daemon serialises with, and the two Python generations the GUI
# picks between at import time.
#
# Each writes the same message and the others read it back. A disagreement
# between any two of them would show up in production as a GUI that starts,
# connects, and silently never displays a scan -- so it is checked here rather
# than discovered there.
#
# The two Python generations need two different runtimes, because that is the
# whole reason there are two of them:
#
#   PYTHON_MODERN   an interpreter whose protobuf runtime is >= 4.0.0
#   PYTHON_LEGACY   an interpreter whose protobuf runtime is >= 3.6, < 3.20
#
# Either may be left unset, in which case that half is reported as skipped.
# PORTSCAN_REQUIRE_BOTH=1 turns a skip into a failure, which is what CI uses.
#
# Usage:
#   PYTHON_MODERN=python3 PYTHON_LEGACY=/path/to/python3.7 ./run_binding_check.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
CHECK="$HERE/check_portscan_bindings.py"
MODERN_PB="$REPO/ui/opensnitch/proto/ui_pb2.py"
LEGACY_PB="$REPO/ui/opensnitch/proto/pre3200/ui_pb2.py"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

PYTHON_MODERN="${PYTHON_MODERN:-python3}"
PYTHON_LEGACY="${PYTHON_LEGACY:-}"

have_modern=0
have_legacy=0
if "$PYTHON_MODERN" -c 'import google.protobuf' 2>/dev/null; then
    have_modern=1
fi
if [ -n "$PYTHON_LEGACY" ] && "$PYTHON_LEGACY" -c 'import google.protobuf' 2>/dev/null; then
    have_legacy=1
fi

if [ "${PORTSCAN_REQUIRE_BOTH:-0}" = "1" ]; then
    [ "$have_modern" = 1 ] || die "PYTHON_MODERN has no protobuf runtime"
    [ "$have_legacy" = 1 ] || die "PYTHON_LEGACY has no protobuf runtime"
fi

# --- the Go side -----------------------------------------------------------
say "building the Go fixture"
GO_FIXTURE="$WORK/protofixture"
( cd "$REPO/daemon" && go build -o "$GO_FIXTURE" ./portscan/testdata/protofixture/ )

say "Go writes"
"$GO_FIXTURE" --write "$WORK/go.bin"

# --- each Python generation reads what Go wrote ----------------------------
if [ "$have_modern" = 1 ]; then
    say "modern Python reads the daemon's bytes"
    "$PYTHON_MODERN" "$CHECK" "$MODERN_PB" --read "$WORK/go.bin"
else
    say "SKIPPED: no modern protobuf runtime"
fi

if [ "$have_legacy" = 1 ]; then
    say "legacy Python reads the daemon's bytes"
    "$PYTHON_LEGACY" "$CHECK" "$LEGACY_PB" --read "$WORK/go.bin"
else
    say "SKIPPED: no legacy protobuf runtime (set PYTHON_LEGACY)"
fi

# --- and the daemon reads what each Python generation wrote ----------------
if [ "$have_modern" = 1 ]; then
    say "modern Python writes, Go reads"
    "$PYTHON_MODERN" "$CHECK" "$MODERN_PB" --write "$WORK/modern.bin"
    "$GO_FIXTURE" --read "$WORK/modern.bin"
    cmp "$WORK/go.bin" "$WORK/modern.bin" \
        || die "modern Python does not encode the alert as Go does"
    say "the encodings are byte-identical"
fi

if [ "$have_legacy" = 1 ]; then
    say "legacy Python writes, Go reads"
    "$PYTHON_LEGACY" "$CHECK" "$LEGACY_PB" --write "$WORK/legacy.bin"
    "$GO_FIXTURE" --read "$WORK/legacy.bin"
    cmp "$WORK/go.bin" "$WORK/legacy.bin" \
        || die "legacy Python does not encode the alert as Go does"
    say "the encodings are byte-identical"
fi

# --- and the two Python generations agree with each other ------------------
if [ "$have_modern" = 1 ] && [ "$have_legacy" = 1 ]; then
    say "each Python generation reads the other's bytes"
    "$PYTHON_LEGACY" "$CHECK" "$LEGACY_PB" --read "$WORK/modern.bin"
    "$PYTHON_MODERN" "$CHECK" "$MODERN_PB" --read "$WORK/legacy.bin"
fi

say "OK"
