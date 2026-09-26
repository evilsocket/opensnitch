#!/usr/bin/env bash
#
# Runs the live end-to-end tests, which need CAP_NET_RAW and CAP_NET_ADMIN.
#
# An unprivileged user namespace grants both inside its own network namespace,
# so no root and no sudo are required:
#
#     ./testdata/run_live_test.sh
#
# PORTSCAN_REQUIRE_LIVE=1 turns "skipped because the environment lacks raw
# sockets" into a failure, which is what CI must use: a test that silently
# skips is a test that stops protecting anything.
set -euo pipefail
cd "$(dirname "$0")/.."
exec unshare -Urn --fork sh -c 'ip link set lo up && exec "$@"' sh \
    env PORTSCAN_REQUIRE_LIVE=1 PORTSCAN_DISPOSABLE_NETNS=1 \
    go test -count=1 -v -run 'TestLiveAFPacket' "$@" .
