//go:build linux

package portscan

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A block keeps the scan that led to it, whichever way it was made, so the
// user can still see the method, the hardware address and the ports once the
// alert is gone.

func TestAutoBlockKeepsItsScan(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	ev := testScanEvent(attacker)
	h.m.handleEvent(ev)

	src, _, _, ok := h.m.BlockInfo(attacker)
	if !ok {
		t.Fatalf("%s is not blocked", attacker)
	}
	if src.Scan != ev {
		t.Fatalf("the block does not carry the scan that made it: %+v", src.Scan)
	}
}

func TestConfirmedBlockKeepsTheLatestScan(t *testing.T) {
	h := newTestMonitor(t, nil) // ask
	first, latest := testScanEvent(attacker), testScanEvent(attacker)
	latest.DistinctPorts = 40
	h.m.handleEvent(first)
	h.m.handleEvent(latest)
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("ConfirmBlock: %v", err)
	}
	src, _, _, ok := h.m.BlockInfo(attacker)
	if !ok {
		t.Fatalf("%s is not blocked", attacker)
	}
	if src.Scan != latest {
		t.Fatalf("the block carries %+v, want the latest detection", src.Scan)
	}
	if src.Reason != "confirmed by the user" {
		t.Fatalf("reason = %q", src.Reason)
	}
}

// TestBlockInfoWithoutARuleReader: a backend that cannot show its rules
// still lets the block be inspected, and says why the rule is missing.
func TestBlockInfoWithoutARuleReader(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	h.m.handleEvent(testScanEvent(attacker))
	src, rule, ruleErr, ok := h.m.BlockInfo(attacker)
	if !ok || src.Addr != attacker {
		t.Fatalf("BlockInfo = %+v, %v", src, ok)
	}
	if rule != "" || ruleErr == nil || !strings.Contains(ruleErr.Error(), "cannot show") {
		t.Fatalf("rule = %q, err = %v; want the reason it is missing", rule, ruleErr)
	}
	if _, _, _, ok := h.m.BlockInfo(victim); ok {
		t.Fatalf("an address that is not blocked has details")
	}
}

func TestReadoptKeepsTheScan(t *testing.T) {
	old, _ := newTestBlockManager(t, newFakeBlocker(), testBlockConfig(), func(netip.Addr) bool { return false })
	a := netip.MustParseAddr("198.51.100.9")
	ev := testScanEvent(a)
	if err := old.BlockScan(a, "scan", ev); err != nil {
		t.Fatal(err)
	}
	m, now := newTestBlockManager(t, newFakeBlocker(), testBlockConfig(), func(netip.Addr) bool { return false })
	*now = time.Unix(1700000000, 0)
	m.Readopt(old.Blocked())
	src, ok := m.Lookup(a)
	if !ok || src.Scan != ev {
		t.Fatalf("after a reload the block carries %+v, %v; want its scan", src.Scan, ok)
	}
}

// TestReblockKeepsAKnownScan: extending a block with no scan to hand, as a
// confirmation for a forgotten proposal does, keeps the one it had.
func TestReblockKeepsAKnownScan(t *testing.T) {
	m, _ := newTestBlockManager(t, newFakeBlocker(), testBlockConfig(), func(netip.Addr) bool { return false })
	a := netip.MustParseAddr("198.51.100.10")
	ev := testScanEvent(a)
	if err := m.BlockScan(a, "scan", ev); err != nil {
		t.Fatal(err)
	}
	if err := m.Block(a, "again"); err != nil {
		t.Fatal(err)
	}
	if src, _ := m.Lookup(a); src.Scan != ev {
		t.Fatalf("re-blocking without a scan dropped the one it had")
	}
}

// TestADetectionWhileBlockedUpdatesTheScan: the source is still scored while
// blocked, and the details show its latest detection, without extending the
// block.
func TestADetectionWhileBlockedUpdatesTheScan(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	first, later := testScanEvent(attacker), testScanEvent(attacker)
	later.DistinctPorts = 300
	h.m.handleEvent(first)
	before, _, _, _ := h.m.BlockInfo(attacker)
	h.m.handleEvent(later)
	after, _, _, ok := h.m.BlockInfo(attacker)
	if !ok || after.Scan != later {
		t.Fatalf("the block shows %+v, want the latest detection", after.Scan)
	}
	if !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatalf("a detection while blocked moved the expiry: %v -> %v", before.ExpiresAt, after.ExpiresAt)
	}
}
