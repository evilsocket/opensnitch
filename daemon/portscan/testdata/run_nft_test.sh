#!/usr/bin/env bash
#
# Runs the nftables enforcement tests, which need CAP_NET_ADMIN and must not be
# allowed to touch the machine's real firewall.
#
# An unprivileged user namespace grants the capability inside a fresh network
# namespace, which starts with an empty ruleset and disappears with the test:
#
#     ./testdata/run_nft_test.sh
#
# PORTSCAN_REQUIRE_NFT=1 turns "skipped because nftables was unavailable" into a
# failure, which is what CI must use: a test that silently skips is a test that
# stops protecting anything.
#
# The nft command line is used to read the ruleset back, so what is asserted is
# what the kernel holds rather than what the library believes it sent.
set -euo pipefail
cd "$(dirname "$0")/.."

# The namespace has no network, so the modules the build needs are fetched
# before entering it; with a warm module cache this does nothing.
go mod download

if ! command -v nft >/dev/null 2>&1; then
    echo "nft is not on PATH; the ruleset cannot be read back independently" >&2
    exit 1
fi

# No -run filter. The privileged tests are skipped by unprivileged runs, so a
# test this runner did not select would run nowhere, and a filter naming them
# would forget the next one added. Running the whole package under the
# namespace cannot drift, costs a few seconds, and exercises every other test with
# CAP_NET_ADMIN available as a bonus. Tests that need nftables skip themselves
# when it is absent, and PORTSCAN_REQUIRE_NFT turns those skips into failures.
# lo comes up DOWN in a fresh namespace. Bringing it up here rather than in
# whichever test happens to run first keeps a single test runnable on its own:
# the monitor tests address their probes to 127.0.0.1.
exec unshare -Urn --fork sh -c 'ip link set lo up && exec "$@"' sh \
    env PORTSCAN_REQUIRE_NFT=1 PORTSCAN_DISPOSABLE_NETNS=1 \
    go test -count=1 -v "$@" .
