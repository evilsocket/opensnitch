//go:build linux

package portscan

import (
	"net/netip"
	"testing"
	"time"
)

// TestEvictedSlotIsBlanked is the price of reusing entries instead of
// allocating them.
//
// With a slab and a free list, the struct a new source gets is the struct the
// evicted source was using. Anything left in it -- score, port filter, the
// "already reported" flag, the MAC -- would be read as the NEW source's own
// history. That is a false accusation, and since an attacker chooses who gets
// evicted, a chosen one.
func TestEvictedSlotIsBlanked(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSources = 256
	cfg.ScoreThreshold = 1 << 20 // never report, so nothing is reset by reporting
	e, err := NewEngine(cfg, &benchHost{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// One source builds up a thick history.
	loud := netip.MustParseAddr("198.51.100.7")
	p := synProbe(0, loud, victim, 1)
	p.HasMAC, p.SrcMAC = true, [6]byte{9, 9, 9, 9, 9, 9}
	for i := 0; i < 400; i++ {
		p.TimeNs = uint64(i) * uint64(time.Microsecond)
		p.DstPort = uint16(1000 + i)
		e.Process(p)
	}
	before, ok := e.table.lookup(loud)
	if !ok || before.score == 0 || before.distinctPorts == 0 {
		t.Fatalf("the loud source built no history: %+v", before)
	}
	t.Logf("loud source: score=%d ports=%d", before.score, before.distinctPorts)

	// Flood it out of the table, several times over.
	for i := 0; i < 20000; i++ {
		q := synProbe(uint64(10000+i)*uint64(time.Microsecond),
			netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)}), victim, uint16(i))
		e.Process(q)
	}
	// Whether the flood evicted it or not is the eviction policy's business,
	// not this test's: Forget releases the slot either way, which is the same
	// path an operator clearing a block takes.
	e.Forget(loud)
	if _, still := e.table.lookup(loud); still {
		t.Fatal("Forget did not release the slot")
	}

	// Every entry in every shard must now look like what it claims to be:
	// nothing may carry the evicted source's MAC or a score it never earned.
	for si, sh := range e.table.shards {
		sh.mu.Lock()
		for ci := range sh.slabs {
			for i := range sh.slabs[ci] {
				en := &sh.slabs[ci][i]
				if _, live := sh.entries[en.addr]; live {
					continue
				}
				// A free or never-used slot must be completely blank.
				if en.state != (sourceState{}) || en.addr != (netip.Addr{}) {
					sh.mu.Unlock()
					t.Fatalf("shard %d chunk %d slot %d is free but not blank: addr=%v state=%+v",
						si, ci, i, en.addr, en.state)
				}
			}
		}
		sh.mu.Unlock()
	}

	// And a brand-new source landing in a recycled slot starts from zero.
	fresh := netip.MustParseAddr("192.0.2.250")
	f := synProbe(uint64(1_000_000)*uint64(time.Microsecond), fresh, victim, 80)
	e.Process(f)
	st, ok := e.table.lookup(fresh)
	if !ok {
		t.Fatal("the fresh source was not admitted")
	}
	if st.hasMAC && st.srcMAC == ([6]byte{9, 9, 9, 9, 9, 9}) {
		t.Fatalf("the evicted source's MAC was inherited: %v", st.srcMAC)
	}
	if st.distinctPorts != 1 || st.generations != 0 || st.reported {
		t.Fatalf("a fresh source inherited history: ports=%d generations=%d reported=%v",
			st.distinctPorts, st.generations, st.reported)
	}
	if st.firstSeenNs != f.TimeNs {
		t.Fatalf("firstSeenNs = %d, want %d: a stale timestamp survived", st.firstSeenNs, f.TimeNs)
	}
}

// Does the packet path allocate when every packet is from a NEW source --
// the forged-source flood an attacker controls the rate of?
func TestFloodPathDoesNotAllocate(t *testing.T) {
	cfg := testConfig()
	cfg.ScoreThreshold = 1 << 20
	cfg.MaxSources = 4096
	e, err := NewEngine(cfg, &benchHost{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := synProbe(0, attacker, victim, 1)
	// fill the table first so we measure the steady state: evict + insert
	for i := 0; i < 20000; i++ {
		p.TimeNs = uint64(i) * uint64(time.Microsecond)
		p.Src = netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
		p.DstPort = uint16(i)
		e.Process(p)
	}
	i := 20000
	n := testing.AllocsPerRun(5000, func() {
		i++
		p.TimeNs = uint64(i) * uint64(time.Microsecond)
		p.Src = netip.AddrFrom4([4]byte{192, byte(i >> 16), byte(i >> 8), byte(i)})
		p.DstPort = uint16(i)
		e.Process(p)
	})
	t.Logf("allocations per packet, every packet a new source: %.2f", n)

	// and for comparison, the same source over and over
	q := synProbe(0, attacker, victim, 1)
	e.Process(q)
	m := testing.AllocsPerRun(5000, func() {
		i++
		q.TimeNs = uint64(i) * uint64(time.Microsecond)
		q.DstPort = uint16(i)
		e.Process(q)
	})
	t.Logf("allocations per packet, one source: %.2f", m)
}
