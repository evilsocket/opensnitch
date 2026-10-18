package portscan

import (
	"net/netip"
	"testing"
	"time"
)

// TestOvercapDoesNotAccumulateOrphans pins MaxBlockedSources across a SEQUENCE
// of backend failures, not just one.
//
// Bounding a single episode at cap+1 is not enough. Across episodes the
// firewall would grow without limit: each time eviction and the take-back-out
// both failed, the address would be in the firewall and recorded nowhere, so
// when the backend recovered the first successful release would clear
// overcap, installing would resume, and the next failure would leave another
// invisible address behind. Measured with only the per-episode bound: one
// orphan per episode, four episodes, four orphans, with the manager listing
// zero.
//
// The user could not see them (Blocked would not list them), could not release
// them (Unblock looks the address up in byAddr first), and nothing would
// expire them but the kernel-side timeout of the nftables set -- four hours by
// default.
func TestOvercapDoesNotAccumulateOrphans(t *testing.T) {
	b := &failingUnblocker{fakeBlocker: newFakeBlocker(), fail: false}
	const maxBlocks = 3
	m, err := NewBlockManager(b, BlockConfig{Duration: time.Hour, MaxBlockedSources: maxBlocks},
		func(netip.Addr) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	m.SetOnError(func(error) {})

	addr := func(ep, i int) netip.Addr {
		return netip.AddrFrom4([4]byte{198, 51, byte(ep), byte(i)})
	}

	const episodes = 4
	for ep := 1; ep <= episodes; ep++ {
		// 1. Fill to the cap with a healthy backend.
		b.fail = false
		for i := 0; i < maxBlocks; i++ {
			if err := m.Block(addr(ep, i), "scan"); err != nil {
				t.Fatalf("episode %d: filling to the cap: %v", ep, err)
			}
		}

		// 2. The backend refuses releases, and one more block arrives. It is
		//    installed, room cannot be made, and it cannot be taken back out.
		b.fail = true
		_ = m.Block(addr(ep, maxBlocks), "scan")

		// 3. The backend recovers and the manager is given its expiry pass.
		b.fail = false
		m.ExpireDue()
		for _, e := range m.Blocked() {
			_ = m.Unblock(e.Addr)
		}

		if n := b.count(); n > maxBlocks {
			t.Fatalf("after episode %d the firewall still drops %d addresses for a cap"+
				" of %d; orphans are accumulating", ep, n, maxBlocks)
		}
		if listed, real := len(m.Blocked()), b.count(); listed != real {
			t.Fatalf("after episode %d the manager lists %d blocks but the firewall drops"+
				" %d: an address the user can neither see nor release",
				ep, listed, real)
		}
	}

	if n := b.count(); n != 0 {
		t.Fatalf("after %d episodes the firewall still drops %d addresses that nothing"+
			" released", episodes, n)
	}
}

// TestOvercapEntryIsVisibleAndReleasable pins the three things losing the entry
// took away: the user can see it, the user can release it, and Stop targets it.
func TestOvercapEntryIsVisibleAndReleasable(t *testing.T) {
	b := &failingUnblocker{fakeBlocker: newFakeBlocker(), fail: false}
	const maxBlocks = 2
	m, err := NewBlockManager(b, BlockConfig{Duration: time.Hour, MaxBlockedSources: maxBlocks},
		func(netip.Addr) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	m.SetOnError(func(error) {})

	for i := 0; i < maxBlocks; i++ {
		if err := m.Block(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), "scan"); err != nil {
			t.Fatal(err)
		}
	}

	over := netip.MustParseAddr("198.51.100.200")
	b.fail = true
	_ = m.Block(over, "scan")
	b.fail = false

	found := false
	for _, e := range m.Blocked() {
		if e.Addr == over {
			found = true
		}
	}
	if !found {
		t.Fatalf("%v is in the firewall but Blocked() does not list it", over)
	}

	if err := m.Unblock(over); err != nil {
		t.Fatalf("releasing the over-cap address: %v", err)
	}
	for _, e := range m.Blocked() {
		if e.Addr == over {
			t.Fatalf("%v was released by the manager but is still listed", over)
		}
	}
	if b.count() != maxBlocks {
		t.Fatalf("the firewall drops %d addresses after the release, want %d", b.count(), maxBlocks)
	}
}
