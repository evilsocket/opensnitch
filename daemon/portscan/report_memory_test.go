package portscan

import (
	"net/netip"
	"testing"
	"time"
)

// srcN builds the i-th distinct source address.
func srcN(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{198, 51, byte(i / 256), byte(i % 256)})
}

// crossOnce drives one source over the threshold at a single timestamp:
// eleven SYNs to distinct system ports, 11*12 = 132 against a threshold of 100.
//
// Eleven rather than the nine that would just suffice: the tests built on this
// helper are about what happens once a source crosses, and a margin of more
// than one port keeps them from depending on the exact weights.
func crossOnce(e *Engine, src netip.Addr, tNs uint64, portBase uint16) *ScanEvent {
	var ev *ScanEvent
	for k := 0; k < 11; k++ {
		if got := e.Process(synProbe(tNs, src, victim, portBase+uint16(k))); got != nil && ev == nil {
			ev = got
		}
	}
	return ev
}

// TestEvictionKeepsTheReportCooldown pins that forcing a reported source out of
// the table does not buy a fresh alert.
//
// The eviction bias cannot carry this on its own. evictOne compares the last
// evictScanDepth entries and always evicts one of them, so a constant bias added
// to every candidate cancels out; it only discriminates when some candidate is
// not reported. A decoy scan fills the table with reported sources by
// construction -- that is what nmap -D does, and it is the case the alert
// limiter exists for -- after which one forged probe would evict a reported
// source and take its cooldown with it. Measured without the report memory:
// re-alert 200 ms after the first alert, against a cooldown of one hour.
func TestEvictionKeepsTheReportCooldown(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSources = 64 // one shard
	cfg.AlertsPerMinute = 600
	cfg.ReportCooldown = time.Hour
	e := newTestEngine(t, cfg, newFakeHost())

	const t0 = uint64(3600) * sec

	reported := make([]netip.Addr, 0, 64)
	for i := 0; i < 64; i++ {
		s := srcN(i)
		if ev := crossOnce(e, s, t0+uint64(i)*ms, 1); ev == nil {
			t.Fatalf("source %d did not cross the threshold", i)
		}
		reported = append(reported, s)
	}

	// One more distinct source forces an eviction among candidates that are all
	// reported, which is precisely the case the bias cannot resolve.
	e.Process(synProbe(t0+100*ms, netip.MustParseAddr("203.0.113.9"), victim, 80))

	var evicted netip.Addr
	for _, s := range reported {
		if _, ok := e.table.lookup(s); !ok {
			evicted = s
			break
		}
	}
	if !evicted.IsValid() {
		t.Skip("no reported source was evicted; this test has nothing to check")
	}

	if ev := crossOnce(e, evicted, t0+200*ms, 500); ev != nil {
		t.Fatalf("%v was evicted and re-alerted 200 ms after being reported,"+
			" inside a one-hour cooldown", evicted)
	}

	// And the recovered entry must say so, not merely stay quiet: ConfirmBlock
	// gates on Reported, so an attacker who can clear that flag by forcing an
	// eviction can have a block confirmed for a source the daemon no longer
	// believes it reported.
	if d := e.LookupForBlock(evicted); !d.Reported {
		t.Fatalf("%v came back after eviction with Reported false", evicted)
	}
}

// TestEvictionKeepsTheSuppressionWindow is the same defect seen through the
// other rate limit: a source refused by AlertsPerMinute records the window it
// was refused in, and losing that record lets it ask again inside the window.
func TestEvictionKeepsTheSuppressionWindow(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSources = 64
	cfg.AlertsPerMinute = 1
	cfg.ReportCooldown = time.Hour
	e := newTestEngine(t, cfg, newFakeHost())

	const t0 = uint64(3600) * sec

	crossOnce(e, srcN(0), t0, 1) // takes the single alert slot
	if ev := crossOnce(e, srcN(1), t0+ms, 100); ev != nil {
		t.Fatal("the second source crossed inside a one-alert window and was not refused")
	}
	st, ok := e.table.lookup(srcN(1))
	if !ok {
		t.Fatal("the refused source was not tracked")
	}
	if st.suppressedUntilNs == 0 {
		t.Fatal("a refused source recorded no suppression window")
	}
	want := st.suppressedUntilNs

	// Fill the shard so that eviction reaches srcN(1).
	for i := 2; i < 70; i++ {
		crossOnce(e, srcN(i), t0+uint64(i)*ms, uint16(1+10*i))
	}
	if _, ok := e.table.lookup(srcN(1)); ok {
		t.Skip("srcN(1) survived; this test has nothing to check")
	}

	// It comes back on its next packet, and must come back suppressed.
	e.Process(synProbe(t0+90*ms, srcN(1), victim, 100))
	st, ok = e.table.lookup(srcN(1))
	if !ok {
		t.Fatal("the source was not re-admitted")
	}
	if st.suppressedUntilNs != want {
		t.Fatalf("suppression window after eviction = %d, want %d",
			st.suppressedUntilNs, want)
	}
}

// TestReportMemoryIsBounded pins that the memory cannot grow without limit, and
// that its ring evicts oldest-first. It is the only unbounded-growth risk the
// report memory brings, so it is checked rather than argued.
func TestReportMemoryIsBounded(t *testing.T) {
	tbl := newSourceTable(1024, uint64(time.Second), 100)
	for i := 0; i < 10*reportMemoPerShard; i++ {
		tbl.remember(srcN(i), uint64(i), 0, true, true)
	}
	if len(tbl.memoAt) != reportMemoPerShard {
		t.Fatalf("memo index holds %d addresses, want %d", len(tbl.memoAt), reportMemoPerShard)
	}
	if len(tbl.memo) != reportMemoPerShard {
		t.Fatalf("memo ring holds %d slots, want %d", len(tbl.memo), reportMemoPerShard)
	}
	// The most recent reportMemoPerShard addresses are the ones kept.
	for i := 10*reportMemoPerShard - reportMemoPerShard; i < 10*reportMemoPerShard; i++ {
		if _, ok := tbl.memoAt[srcN(i)]; !ok {
			t.Fatalf("address %v was dropped from the memo while newer ones were kept", srcN(i))
		}
	}
	if _, ok := tbl.memoAt[srcN(0)]; ok {
		t.Fatal("the oldest address is still in the memo after ten times its capacity")
	}

	// Re-remembering an address already held updates it in place rather than
	// consuming another slot.
	before := len(tbl.memoAt)
	last := srcN(10*reportMemoPerShard - 1)
	tbl.remember(last, 42, 43, true, true)
	if len(tbl.memoAt) != before {
		t.Fatalf("re-remembering a known address changed the memo size to %d, want %d",
			len(tbl.memoAt), before)
	}
	var st sourceState
	tbl.recall(last, &st)
	if st.reportedAtNs != 42 || st.suppressedUntilNs != 43 {
		t.Fatalf("recall returned %d/%d, want 42/43", st.reportedAtNs, st.suppressedUntilNs)
	}
}

// TestReportMemoryDoesNotRefreshTheCooldown pins the direction of the report
// memory: a remembered report keeps its ORIGINAL timestamp. Refreshing it on
// every recall would let an attacker extend their own cooldown indefinitely by
// forcing evictions -- the same defect, inverted.
func TestReportMemoryDoesNotRefreshTheCooldown(t *testing.T) {
	tbl := newSourceTable(1024, uint64(time.Second), 100)
	tbl.remember(srcN(7), 1000, 2000, true, true)

	var st sourceState
	tbl.recall(srcN(7), &st)
	tbl.recall(srcN(7), &st)
	if st.reportedAtNs != 1000 || st.suppressedUntilNs != 2000 {
		t.Fatalf("after two recalls: %d/%d, want 1000/2000",
			st.reportedAtNs, st.suppressedUntilNs)
	}
	if !st.reported {
		t.Fatal("recall did not restore the reported flag")
	}
}

// TestReportMemoryRingDoesNotFreeze pins that a reported slot under the cursor
// does not stop every later suppression from being recorded.
//
// The refusal rule -- a report is never displaced by a mere suppression --
// must still advance the cursor. If it returned without doing so, once the
// cursor landed on a reported slot it would stay there, and every
// suppressed-only write would be refused for ever. Measured that way: after
// one report, 63 of 640 writes were accepted and zero after that,
// permanently. It is reachable from forged traffic alone, since the cheapest
// crossing costs five packets, so a few hundred forged sources would park the
// cursor on a slot the attacker's own alert occupies.
func TestReportMemoryRingDoesNotFreeze(t *testing.T) {
	tbl := newSourceTable(1024, uint64(time.Second), 100)

	// One report, then park the cursor on it by filling the rest of the ring.
	tbl.remember(srcN(0), 1000, 0, true, true)
	for i := 1; i < reportMemoPerShard; i++ {
		tbl.remember(srcN(i), 0, uint64(i), false, false)
	}

	accepted := 0
	for i := 0; i < 10*reportMemoPerShard; i++ {
		a := srcN(1000 + i)
		tbl.remember(a, 0, uint64(i+1), false, false)
		if _, ok := tbl.memoAt[a]; ok {
			accepted++
		}
	}
	if accepted == 0 {
		t.Fatal("the ring froze: no suppression was recorded after a report took a slot")
	}
	// Every later write lands somewhere, bar the one reported slot it must not take.
	if accepted < 10*reportMemoPerShard-reportMemoPerShard {
		t.Fatalf("only %d of %d suppressions were recorded; the ring is stalling",
			accepted, 10*reportMemoPerShard)
	}

	// And the report it was protecting is still there, with its own timestamp.
	var st sourceState
	tbl.recall(srcN(0), &st)
	if !st.reported || st.reportedAtNs != 1000 {
		t.Fatalf("the reported slot was displaced by a suppression: reported=%v at=%d",
			st.reported, st.reportedAtNs)
	}
}

// TestReportMemoryRingKeepsReportsWhenFull pins the other side: when every slot
// holds a report, a suppression is dropped rather than displacing one.
func TestReportMemoryRingKeepsReportsWhenFull(t *testing.T) {
	tbl := newSourceTable(1024, uint64(time.Second), 100)
	for i := 0; i < reportMemoPerShard; i++ {
		tbl.remember(srcN(i), uint64(1000+i), 0, true, true)
	}
	tbl.remember(srcN(9999), 0, 5, false, false)
	if _, ok := tbl.memoAt[srcN(9999)]; ok {
		t.Fatal("a suppression displaced a report in a ring full of reports")
	}
	for i := 0; i < reportMemoPerShard; i++ {
		var st sourceState
		tbl.recall(srcN(i), &st)
		if !st.reported {
			t.Fatalf("report %d was lost", i)
		}
	}
}

// TestIdleExpiryKeepsTheReportCooldown pins that going quiet forgets no more
// than being evicted does.
//
// Only eviction remembered. A source pushed out by pressure kept its cooldown
// while one that simply fell idle lost it, so the cooldown held or not depending
// on which path reached the entry first -- safe only while IdleExpiry outlasts
// ReportCooldown, which stops being true the moment an operator raises the
// cooldown to quieten a noisy host.
func TestIdleExpiryKeepsTheReportCooldown(t *testing.T) {
	cfg := testConfig()
	cfg.ReportCooldown = time.Hour
	cfg.IdleExpiry = time.Minute
	e := newTestEngine(t, cfg, newFakeHost())

	const t0 = uint64(3600) * sec
	if ev := crossOnce(e, srcN(0), t0, 1); ev == nil {
		t.Fatal("the source did not cross")
	}

	// Two minutes of silence: past IdleExpiry, far inside ReportCooldown.
	e.Expire(t0 + 120*sec)
	if _, ok := e.table.lookup(srcN(0)); ok {
		t.Skip("the entry was not expired; this test has nothing to check")
	}

	if ev := crossOnce(e, srcN(0), t0+121*sec, 500); ev != nil {
		t.Fatal("a source that went idle re-alerted two minutes after being reported," +
			" inside a one-hour cooldown")
	}
}

// TestTheMemoryKeepsWhetherTheLastReportCouldBeBlocked: a source reported
// first as blockable, then, after its entry expired, as not blockable, must
// still be reported as soon as it becomes blockable again. The memory records
// the last report, not every report: kept from the first one, the source would
// come back from its next expiry owing the whole cooldown, and the SYN scan
// that follows a cheap report would go unasked and unblocked.
func TestTheMemoryKeepsWhetherTheLastReportCouldBeBlocked(t *testing.T) {
	cfg := testConfig()
	cfg.ReportCooldown = time.Hour // longer than IdleExpiry, so the memory decides
	e := newTestEngine(t, cfg, newFakeHost())
	now := sec
	scan := func(probe func(now uint64, port uint16) *Probe, base uint16, n int) []*ScanEvent {
		var out []*ScanEvent
		for k := 0; k < n; k++ {
			if ev := e.Process(probe(now, base+uint16(k))); ev != nil {
				out = append(out, ev)
			}
			now += ms
		}
		return out
	}
	syn := func(now uint64, p uint16) *Probe { return synProbe(now, attacker, victim, p) }
	udp := func(now uint64, p uint16) *Probe { return udpProbe(now, attacker, victim, p) }
	expire := func() {
		now += 31 * uint64(time.Minute)
		e.Expire(now)
		if _, ok := e.table.lookup(attacker); ok {
			t.Fatal("the entry did not expire; the test does not exercise the memory")
		}
	}

	if r := scan(syn, 1, 20); len(r) != 1 || !r[0].BlockEligible {
		t.Fatalf("first report: %d events, want one that can be blocked", len(r))
	}
	expire()
	expire() // past the cooldown of the first report
	if r := scan(udp, 1000, 200); len(r) != 1 || r[0].BlockEligible {
		t.Fatalf("second report: %d events, want one that cannot be blocked", len(r))
	}
	expire()
	if r := scan(syn, 1, 200); len(r) != 1 || !r[0].BlockEligible {
		t.Fatalf("the SYN scan after a report that could not be blocked gave %d events;"+
			" want one that can be, inside the cooldown", len(r))
	}
}
