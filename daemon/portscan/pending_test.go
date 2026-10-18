//go:build linux

package portscan

import (
	"net/netip"
	"testing"
	"time"
)

// TestDecoysCannotBuySilence pins that crowding the alert limiter does not stop
// the real scanner being named.
//
// The limiter is global -- three alerts a minute across every source. If a
// source refused a slot got another chance only when another probe arrived
// from it, a scanner that scans and then stops, sending no such probe, would
// never have its crossing surfaced at all. Measured without the queue: three
// forged decoy sources of nine SYNs each, 27 packets in total, emitted just
// before the real scan, and the scanner was never named; the user saw three
// alerts for three innocent addresses instead.
func TestDecoysCannotBuySilence(t *testing.T) {
	cfg := testConfig()
	cfg.AlertsPerMinute = 3
	cfg.ReportCooldown = time.Hour
	e := newTestEngine(t, cfg, newFakeHost())

	const t0 = uint64(3600) * sec
	local := netip.MustParseAddr("192.0.2.1")
	scanner := netip.MustParseAddr("203.0.113.66")

	// Three decoys take the whole window.
	named := map[netip.Addr]bool{}
	for d := 0; d < 3; d++ {
		src := netip.AddrFrom4([4]byte{198, 51, 100, byte(d)})
		for k := 0; k < 11; k++ {
			if ev := e.Process(synProbe(t0+uint64(d*20+k)*ms, src, local, uint16(21+k))); ev != nil {
				named[ev.Src] = true
			}
		}
	}
	if len(named) != 3 {
		t.Fatalf("%d decoys were reported, want 3: the window was not filled", len(named))
	}

	// The real scan, in the same window, then stops.
	for k := 0; k < 300; k++ {
		if ev := e.Process(synProbe(t0+1000*ms+uint64(k)*ms, scanner, local, uint16(1+k))); ev != nil {
			named[ev.Src] = true
		}
	}
	if named[scanner] {
		t.Skip("the scanner was named inline; this test has nothing to add")
	}

	// A minute later the maintenance pass drains what was queued. No further
	// packet from the scanner: it has finished.
	got := e.DrainPending(t0 + 61*sec)
	for _, ev := range got {
		named[ev.Src] = true
	}
	if !named[scanner] {
		t.Fatalf("the scanner was never named: %d decoys silenced it permanently"+
			" for 33 forged packets", 3)
	}

	// And it is named FIRST, because it scored far more than the decoys.
	if len(got) > 0 && got[0].Src != scanner {
		t.Errorf("the queue surfaced %v before the real scanner: the ranking is not"+
			" by score", got[0].Src)
	}
}

// TestPendingQueueIsBounded pins that queueing crossings cannot grow without
// limit, and that a flood of cheap ones cannot push out an expensive one.
func TestPendingQueueIsBounded(t *testing.T) {
	p := newPendingReports()
	for i := 0; i < 10*maxPendingReports; i++ {
		p.add(&ScanEvent{
			Src:   netip.AddrFrom4([4]byte{198, 51, byte(i / 256), byte(i % 256)}),
			Score: 100,
		})
	}
	if n := p.len(); n != maxPendingReports {
		t.Fatalf("the queue holds %d, want at most %d", n, maxPendingReports)
	}

	// A high score gets in even when the queue is full of cheap ones.
	big := netip.MustParseAddr("203.0.113.200")
	p.add(&ScanEvent{Src: big, Score: 100000})
	first := p.take(1)
	if len(first) != 1 || first[0].Src != big {
		t.Fatalf("the highest-scoring crossing did not come out first: %v", first)
	}
}

// TestAQueueHeldFullStillNamesTheRealScan pins that filling the queue with
// cheap crossings does not silence an expensive one.
//
// The score is capped at twice the threshold. A queue that made room only for
// a strictly higher SCORE would, once full of crossings at that ceiling,
// refuse everything, including another crossing at the ceiling -- that is,
// including a complete scan. The cheapest route to the ceiling is seventeen
// SYNs to closed system ports from a forged address; measured with such a
// queue, 1088 packets filled it and 103 a minute held it full, while a real
// 1000-port scan was never named once in a simulated day: the silence the
// queue exists to remove, bought for slightly more packets.
func TestAQueueHeldFullStillNamesTheRealScan(t *testing.T) {
	p := newPendingReports()

	// Fill it with ceiling-score crossings that touched few ports.
	for i := 0; i < maxPendingReports; i++ {
		p.add(&ScanEvent{
			Src:           netip.AddrFrom4([4]byte{198, 51, byte(i / 256), byte(i % 256)}),
			Score:         200,
			DistinctPorts: 17,
		})
	}
	if p.len() != maxPendingReports {
		t.Fatalf("queue holds %d, want %d", p.len(), maxPendingReports)
	}

	// A real scan: same ceiling score, a thousand ports.
	real := netip.MustParseAddr("203.0.113.99")
	p.add(&ScanEvent{Src: real, Score: 200, DistinctPorts: 1000})

	got := p.take(1)
	if len(got) != 1 || got[0].Src != real {
		t.Fatalf("the queue surfaced %v first; a scan touching a thousand ports"+
			" must outrank crossings that touched seventeen", got)
	}
}

// TestDrainingSpendsOneSlotPerEvent pins that draining does not consume alert
// budget it has nothing to spend it on.
//
// DrainPending asked the limiter for a slot before knowing whether the queue
// held anything, and a slot asked for is a slot spent: allowEvent increments
// the count and nothing gives it back. Draining one queued event consumed two
// of the three alerts allowed that minute and counted two as emitted.
func TestDrainingSpendsOneSlotPerEvent(t *testing.T) {
	cfg := testConfig()
	cfg.AlertsPerMinute = 3
	e := newTestEngine(t, cfg, newFakeHost())

	e.pending.add(&ScanEvent{
		Src:           netip.MustParseAddr("203.0.113.50"),
		Score:         150,
		DistinctPorts: 40,
	})

	const now = uint64(3600) * sec
	got := e.DrainPending(now)
	if len(got) != 1 {
		t.Fatalf("drained %d events, want 1", len(got))
	}

	// Two alerts must still be available in this window.
	left := 0
	for i := 0; i < 5; i++ {
		if ok, _, _ := e.allowEvent(now); ok {
			left++
		}
	}
	if left != 2 {
		t.Fatalf("%d alerts left in the window after draining one event, want 2:"+
			" the drain is spending budget on nothing", left)
	}
	if st := e.Stats(); st.EventsEmitted != 1 {
		t.Errorf("EventsEmitted = %d after draining one event, want 1", st.EventsEmitted)
	}
}

// TestDecoysListedBeforeTheScannerCannotHideIt is nmap -D d1,...,dN,ME: every
// decoy sends exactly what the real scanner sends, so all of them tie in the
// queue, and ME crosses last. A full queue that refused ties would let 67
// decoys keep the real scanner from ever being named, even for a six-minute
// scan.
func TestDecoysListedBeforeTheScannerCannotHideIt(t *testing.T) {
	for _, n := range []int{67, 100, 200} {
		e := newTestEngine(t, testConfig(), newFakeHost())
		local := netip.MustParseAddr("192.0.2.1")
		real := netip.MustParseAddr("203.0.113.200")
		var all []netip.Addr
		for i := 0; i < n; i++ {
			all = append(all, netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i + 1)}))
		}
		all = append(all, real)

		named := false
		at := sec
		lastDrain := at
		for port := 1; port <= 1000; port++ {
			for _, s := range all {
				if ev := e.Process(synProbe(at, s, local, uint16(port))); ev != nil && ev.Src == real {
					named = true
				}
				at += 10 * uint64(time.Microsecond)
			}
			if at-lastDrain >= 60*sec {
				lastDrain = at
				for _, ev := range e.DrainPending(at) {
					named = named || ev.Src == real
				}
			}
		}
		// A day of the drain the monitor runs once a minute.
		for m := 1; m <= 24*60 && !named; m++ {
			now := at + uint64(m)*60*sec
			e.Expire(now)
			for _, ev := range e.DrainPending(now) {
				named = named || ev.Src == real
			}
		}
		if !named {
			t.Errorf("nmap -D with %d decoys listed before ME: the real scanner was"+
				" never named in a day", n)
		}
	}
}

// TestDrainPendingHonoursTheAlertLimit: a queue of ten comes out three at a
// time, not all at once.
func TestDrainPendingHonoursTheAlertLimit(t *testing.T) {
	cfg := testConfig()
	cfg.AlertsPerMinute = 3
	e := newTestEngine(t, cfg, newFakeHost())
	for i := 0; i < 10; i++ {
		e.pending.add(&ScanEvent{Src: netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + i)}), Score: 150})
	}
	const now = uint64(3600) * sec
	if got := len(e.DrainPending(now)); got != cfg.AlertsPerMinute {
		t.Fatalf("one drain emitted %d events with AlertsPerMinute=%d", got, cfg.AlertsPerMinute)
	}
}

// TestARefusedDrainIsNotASuppressedAlert: the queued event was counted as
// suppressed when it was queued. Counting every refused drain as well made the
// figure grow by one a minute for as long as the limiter stayed saturated.
func TestARefusedDrainIsNotASuppressedAlert(t *testing.T) {
	cfg := testConfig()
	cfg.AlertsPerMinute = 1
	e := newTestEngine(t, cfg, newFakeHost())
	local := netip.MustParseAddr("192.0.2.1")
	a := netip.MustParseAddr("203.0.113.1")
	b := netip.MustParseAddr("203.0.113.2")
	for p := 1; p <= 12; p++ {
		e.Process(synProbe(sec+uint64(p), a, local, uint16(p)))
	}
	for p := 1; p <= 12; p++ {
		e.Process(synProbe(sec+100+uint64(p), b, local, uint16(p)))
	}
	for i := 1; i <= 5; i++ {
		if got := e.DrainPending(sec + uint64(i)*5*sec); len(got) != 0 {
			t.Fatalf("drain %d inside the saturated window emitted %d events", i, len(got))
		}
	}
	out := e.DrainPending(sec + 61*sec)
	if len(out) != 1 || out[0].Src != b {
		t.Fatalf("the next window's drain emitted %v, want the one held-back source", out)
	}
	if out[0].SuppressedSince != 1 {
		t.Fatalf("SuppressedSince = %d with one source held back: refused drains"+
			" were counted as suppressed alerts", out[0].SuppressedSince)
	}
}

// TestASourceNamedFromTheQueueIsNotRenamedWithNothingNew: the drain path must
// record the evidence baseline the direct path records. Otherwise a peer
// looping over 70 UDP ports would be named 240 times a day as soon as three
// other crossings a minute kept the limiter saturated.
func TestASourceNamedFromTheQueueIsNotRenamedWithNothingNew(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	local := netip.MustParseAddr("192.0.2.1")
	peer := netip.MustParseAddr("198.51.100.7")
	alerts, noiseN := 0, 0
	for s := 0; s < 86400; s++ {
		at := sec + uint64(s)*sec
		if s%60 == 0 {
			e.Expire(at)
			for _, ev := range e.DrainPending(at) {
				if ev.Src == peer {
					alerts++
				}
			}
			for k := 0; k < 3; k++ {
				noiseN++
				src := netip.AddrFrom4([4]byte{10, byte(noiseN >> 16), byte(noiseN >> 8), byte(noiseN)})
				for p := 0; p < 12; p++ {
					e.Process(synProbe(at+uint64(p), src, local, uint16(1+p)))
				}
			}
		}
		if ev := e.Process(udpProbe(at, peer, local, uint16(20000+(s%70)*7))); ev != nil {
			alerts++
		}
	}
	if alerts > 3 {
		t.Fatalf("%d alerts in a day for a peer looping over 70 ports, named through"+
			" the queue: the evidence gate does not hold on the drain path", alerts)
	}
}

// TestAFastScanIsQueuedForWhatItDid: a scan refused by the limiter was queued
// as it stood at the packet that crossed -- nine ports into a thousand -- and
// a fast scan is over before the next window lets it ask again. Forged sources
// sending seven Xmas probes each cross with a higher score than those nine
// SYNs, so three of them a minute kept a finished 1000-port scan out of the
// alerts for a day, and a burst of 4100 had it evicted from the queue for good.
// When it was named, the alert said nine ports.
func TestAFastScanIsQueuedForWhatItDid(t *testing.T) {
	for _, c := range []struct {
		name             string
		perMinute, burst int
		decoyPorts       int
		xmas             bool
	}{
		{"3 Xmas decoys of 7 probes a minute", 3, 0, 7, true},
		{"a burst of 4100 Xmas decoys of 7 probes", 0, 4100, 7, true},
		{"a burst of 4100 SYN decoys of 10 probes", 0, 4100, 10, false},
	} {
		e := newTestEngine(t, testConfig(), newFakeHost())
		real := netip.MustParseAddr("203.0.113.66")
		now := 3600 * sec
		var realEv *ScanEvent
		seen := func(ev *ScanEvent) {
			if ev != nil && ev.Src == real && realEv == nil {
				realEv = ev
			}
		}
		n := 0
		decoy := func(ports int, xmas bool) {
			src := netip.AddrFrom4([4]byte{198, 18, byte(n >> 8), byte(n)})
			n++
			for k := 0; k < ports; k++ {
				p := synProbe(now, src, victim, uint16(1+k))
				if xmas {
					p.TCPFlags = TCPFin | TCPPsh | TCPUrg
				}
				seen(e.Process(p))
				now += ms
			}
		}
		// Three decoys spend the minute's alerts, then the real scan: a thousand
		// ports in five seconds, refused by the limiter at its ninth.
		for i := 0; i < 3; i++ {
			decoy(10, false)
		}
		for k := 0; k < 1000; k++ {
			seen(e.Process(synProbe(now, real, victim, uint16(1+k))))
			now += 5 * ms
		}
		for i := 0; i < c.burst; i++ {
			decoy(c.decoyPorts, c.xmas)
		}
		start := now
		for m := 1; m <= 5 && realEv == nil; m++ {
			for i := 0; i < c.perMinute; i++ {
				decoy(c.decoyPorts, c.xmas)
			}
			now = start + uint64(m)*60*sec
			for _, ev := range e.DrainPending(now) {
				seen(ev)
			}
		}
		if realEv == nil {
			t.Errorf("%s: a finished 1000-port scan was not named in five minutes", c.name)
			continue
		}
		// Ports 1-1000 less the seven of them in the default ExcludedPorts.
		if realEv.DistinctPorts != 993 {
			t.Errorf("%s: the alert says %d ports for a 993-port scan", c.name, realEv.DistinctPorts)
		}
		// The score has leaked a little while the entry waited; the alert
		// gives the one the scan reached.
		if want := 2 * testConfig().ScoreThreshold; realEv.Score != want {
			t.Errorf("%s: the alert gives score %d, want the %d the scan reached", c.name, realEv.Score, want)
		}
	}
}

// spendMinute fills the alert limiter's window with three forged crossings.
func spendMinute(e *Engine, at *uint64, first byte) {
	for i := byte(0); i < 3; i++ {
		src := netip.AddrFrom4([4]byte{198, 18, first, i})
		for k := 0; k < 10; k++ {
			e.Process(synProbe(*at, src, victim, uint16(1+k)))
			*at += ms
		}
	}
}

// TestAQueuedEntryFollowsFactsNotPackets: the entry of a queued source is
// rewritten when what it has shown doubles, not on every packet it sends. A
// source repeating ports it has sent must not put a queue update, under the
// queue's global lock, on each of its packets.
func TestAQueuedEntryFollowsFactsNotPackets(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := 3600 * sec
	spendMinute(e, &at, 0)
	for k := 0; k < 20; k++ {
		e.Process(synProbe(at, attacker, victim, uint16(1000+k)))
		at += ms
	}
	entry := func() *pendingEntry {
		e.pending.mu.Lock()
		defer e.pending.mu.Unlock()
		return e.pending.byID[attacker]
	}
	queued := entry()
	if queued == nil {
		t.Fatal("the source was not queued; the test does not exercise its case")
	}
	for i := 0; i < 10000; i++ {
		e.Process(synProbe(at, attacker, victim, uint16(1000+i%20)))
		at += 10 * uint64(time.Microsecond)
	}
	if entry() != queued {
		t.Fatal("repeated ports rewrote the queue entry")
	}
	// A few new ports, short of doubling, are not a rewrite either: one per
	// new port would put the queue's lock on every packet of a fast scan.
	for k := 20; k < 30; k++ {
		e.Process(synProbe(at, attacker, victim, uint16(1000+k)))
		at += ms
	}
	if entry() != queued {
		t.Fatal("new ports short of doubling rewrote the queue entry")
	}
	for k := 30; k < 40; k++ {
		e.Process(synProbe(at, attacker, victim, uint16(1000+k)))
		at += ms
	}
	// Queued at 18 ports (twice the 9 it crossed with), so rewritten at 36.
	if got := entry(); got == queued || got.ev.DistinctPorts < 36 {
		t.Fatal("twice the ports did not update the queue entry")
	}
}

// TestADrainedEntryIsNotRefreshedFromAnotherSource: at the drain, a queued
// event is brought up to date from the source's state -- but only the state it
// was queued from. Once that state has expired, the same address sending one
// packet is a new source, and its state says nothing about the scan queued.
func TestADrainedEntryIsNotRefreshedFromAnotherSource(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := 3600 * sec
	spendMinute(e, &at, 0)
	for k := 0; k < 100; k++ {
		e.Process(synProbe(at, attacker, victim, uint16(1+k)))
		at += ms
	}
	at += uint64(DefaultIdleExpiry) + sec
	e.Expire(at)
	e.Process(synProbe(at, attacker, victim, 4444))
	var got *ScanEvent
	for _, ev := range e.DrainPending(at + sec) {
		if ev.Src == attacker {
			got = ev
		}
	}
	if got == nil {
		t.Fatal("the queued scan was not drained; the test does not exercise its case")
	}
	if got.DistinctPorts < 9 {
		t.Fatalf("the queued scan was reported with %d ports: rebuilt from a later"+
			" source at the same address", got.DistinctPorts)
	}
}

// TestRequeueingKeepsTheDraw: a source replacing its own queued entry keeps
// the tie it drew the first time. Were it drawn again, a decoy could re-queue
// until it drew high and so choose its place among equals.
func TestRequeueingKeepsTheDraw(t *testing.T) {
	p := newPendingReports()
	src := netip.MustParseAddr("198.51.100.9")
	p.add(&ScanEvent{Src: src, Score: 120, DistinctPorts: 10})
	tie := p.byID[src].tie
	for i := 0; i < 1000; i++ {
		p.add(&ScanEvent{Src: src, Score: 120, DistinctPorts: 10})
		if got := p.byID[src].tie; got != tie {
			t.Fatalf("re-queueing drew again (%d, then %d)", tie, got)
		}
	}
}

// TestAFullQueueRefusesALowerNewcomer: a full queue gives up its lowest entry
// only for a newcomer ranked above it; a lower one is refused and the queue
// keeps what it had.
func TestAFullQueueRefusesALowerNewcomer(t *testing.T) {
	p := newPendingReports()
	for i := 0; i < maxPendingReports; i++ {
		p.add(&ScanEvent{
			Src:           netip.AddrFrom4([4]byte{198, 51, byte(i / 256), byte(i % 256)}),
			Score:         150,
			DistinctPorts: 20,
		})
	}
	lowest := p.order[0]
	low := netip.MustParseAddr("203.0.113.5")
	p.add(&ScanEvent{Src: low, Score: 110, DistinctPorts: 9})
	if _, in := p.byID[low]; in {
		t.Fatal("a newcomer ranked below the whole of a full queue was let in")
	}
	if p.len() != maxPendingReports || p.order[0] != lowest {
		t.Fatal("a refused newcomer still evicted an entry")
	}
}

// TestADrainedAlertGivesTheScoreTheScanReached: the drain rebuilds a queued
// event from the source's state, where the score has leaked while it waited.
// The alert gives the higher of the two, the score the scan reached.
func TestADrainedAlertGivesTheScoreTheScanReached(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := 3600 * sec
	spendMinute(e, &at, 0)
	for k := 0; k < 100; k++ {
		e.Process(synProbe(at, attacker, victim, uint16(1+k)))
		at += ms
	}
	peak := e.Score(attacker)
	// Still in the same limiter window: a port it already sent, which scores
	// nothing and lets the leak be applied.
	at += 50 * sec
	e.Process(synProbe(at, attacker, victim, 100))
	if e.Score(attacker) >= peak {
		t.Fatal("the score did not leak; the test does not exercise its case")
	}
	var got *ScanEvent
	for _, ev := range e.DrainPending(at + 20*sec) {
		if ev.Src == attacker {
			got = ev
		}
	}
	if got == nil || got.Score != peak {
		t.Fatalf("the drained alert gives %v, want score %d", got, peak)
	}
}

// TestADrainDoesNotMarkANewSourceAtTheSameAddress: a queued scan whose source
// expired and came back is reported as queued, but the state at that address
// now belongs to a new source. Marking it reported, with the old scan's
// evidence as its baseline, kept a later, smaller scan from it silent.
func TestADrainDoesNotMarkANewSourceAtTheSameAddress(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := 3600 * sec
	spendMinute(e, &at, 0)
	for k := 0; k < 100; k++ {
		e.Process(synProbe(at, attacker, victim, uint16(1+k)))
		at += ms
	}
	at += uint64(DefaultIdleExpiry) + sec
	e.Expire(at)
	e.Process(synProbe(at, attacker, victim, 4444))
	drained := false
	for _, ev := range e.DrainPending(at + sec) {
		drained = drained || ev.Src == attacker
	}
	if !drained {
		t.Fatal("the queued scan was not drained; the test does not exercise its case")
	}
	at += 10 * 60 * sec
	var got *ScanEvent
	for k := 0; k < 60 && got == nil; k++ {
		got = e.Process(synProbe(at, attacker, victim, uint16(20000+k)))
		at += ms
	}
	if got == nil {
		t.Fatal("a 60-port scan from an address whose earlier source had expired was never reported")
	}
}

// TestADrainedEventKeepsFactsThatExpiredWhileQueued: the drain rebuilds a
// queued event from its source's state, but a protocol scan that waited more
// than IdleExpiry in the queue has had its protocols forgotten, and was
// reported as "unknown", with no protocol, no port and no score. The event is
// rebuilt only when the state still shows all it said.
func TestADrainedEventKeepsFactsThatExpiredWhileQueued(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := 3600 * sec
	spendMinute(e, &at, 0)
	for proto := 100; proto < 110; proto++ {
		e.Process(&Probe{TimeNs: at, Src: attacker, Dst: victim, Proto: uint8(proto)})
		at += ms
	}
	// 31 minutes with the limiter full, the source sending a protocol it
	// already sent.
	for m := 1; m <= 31; m++ {
		at = 3600*sec + uint64(m)*60*sec
		spendMinute(e, &at, byte(m))
		e.Process(&Probe{TimeNs: at, Src: attacker, Dst: victim, Proto: 100})
		at += ms
	}
	var got *ScanEvent
	for m := 0; m < 3000 && got == nil; m++ {
		for _, ev := range e.DrainPending(at + uint64(m+1)*60*sec) {
			if ev.Src == attacker {
				got = ev
			}
		}
	}
	if got == nil {
		t.Fatal("the queued protocol scan was not drained; the test does not exercise its case")
	}
	if !got.IsProtocolScan || got.Protocols != 10 {
		t.Fatalf("the drained protocol scan says protoScan=%v with %d protocols (%s), want the 10 it queued",
			got.IsProtocolScan, got.Protocols, got.Method)
	}
	// What was reported is the queued event, so its facts are the baseline,
	// not the state's: the forgotten protocols coming back are not news.
	at += uint64(3000*60*sec) + uint64(10*time.Minute)
	for proto := 101; proto < 110; proto++ {
		at += ms
		if e.Process(&Probe{TimeNs: at, Src: attacker, Dst: victim, Proto: uint8(proto)}) != nil {
			t.Fatal("protocols the drained alert reported were news again")
		}
	}
}

// TestAQueuedProtocolScanFollowsItsFacts: the queue entry follows every kind
// of fact, not only ports: a protocol scan queued at the fifth protocol is
// rewritten once it has shown twice as many.
func TestAQueuedProtocolScanFollowsItsFacts(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := 3600 * sec
	spendMinute(e, &at, 0)
	send := func(from, to int) {
		for proto := from; proto < to; proto++ {
			e.Process(&Probe{TimeNs: at, Src: attacker, Dst: victim, Proto: uint8(proto)})
			at += ms
		}
	}
	entry := func() *ScanEvent {
		e.pending.mu.Lock()
		defer e.pending.mu.Unlock()
		if pe := e.pending.byID[attacker]; pe != nil {
			return pe.ev
		}
		return nil
	}
	send(100, 105)
	if q := entry(); q == nil || q.Protocols != 5 {
		t.Fatalf("queued as %v; the test does not exercise its case", q)
	}
	send(105, 110)
	if q := entry(); q.Protocols != 10 {
		t.Fatalf("after 10 protocols the queue entry says %d", q.Protocols)
	}
}

// TestADrainedAlertKeepsItsInterface: the event rebuilt at the drain still
// names the interface the scan came in on.
func TestADrainedAlertKeepsItsInterface(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := 3600 * sec
	spendMinute(e, &at, 0)
	for k := 0; k < 30; k++ {
		p := synProbe(at, attacker, victim, uint16(1+k))
		p.IfaceIndex = 7
		e.Process(p)
		at += ms
	}
	var got *ScanEvent
	for _, ev := range e.DrainPending(at + 60*sec) {
		if ev.Src == attacker {
			got = ev
		}
	}
	if got == nil || got.IfaceIndex != 7 {
		t.Fatalf("the drained alert is %v, want one naming interface 7", got)
	}
}

// TestADrainedAlertGivesTheScoreTheScanReachedSinceItWasQueued: the queued
// entry is rewritten only when the facts double, so the source's score can
// have grown past the entry's. The drained alert gives the higher one.
func TestADrainedAlertGivesTheScoreTheScanReachedSinceItWasQueued(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := 3600 * sec
	spendMinute(e, &at, 0)
	// Queued at the ninth port, below the ceiling; seven more ports stay
	// short of the doubling that would rewrite the entry.
	for k := 0; k < 16; k++ {
		e.Process(synProbe(at, attacker, victim, uint16(1+k)))
		at += ms
	}
	now := e.Score(attacker)
	var got *ScanEvent
	for _, ev := range e.DrainPending(at + 60*sec) {
		if ev.Src == attacker {
			got = ev
		}
	}
	if got == nil || got.Score != now {
		t.Fatalf("the drained alert is %v, want score %d", got, now)
	}
}

// TestADrainKeepsTheBaselineItHad: a report from the queue raises the
// evidence baseline, kind by kind, as an inline report does. Set to the
// drained event instead, it would fall back for the kinds that event showed
// less of: a protocol scan reported earlier, its protocols forgotten, a port
// scan then named from the queue, and the same protocols coming back would be
// news.
func TestADrainKeepsTheBaselineItHad(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := 3600 * sec
	protos := []uint8{50, 51, 4, 41, 94, 132, 136}
	send := func(ps []uint8) (reported bool) {
		for _, proto := range ps {
			at += ms
			reported = e.Process(&Probe{TimeNs: at, Src: attacker, Dst: victim, Proto: proto}) != nil || reported
		}
		return reported
	}
	if !send(append([]uint8{47}, protos...)) {
		t.Fatal("the protocol scan was not reported; the test does not exercise its case")
	}
	for i := 0; i < 3; i++ {
		at += uint64(20 * time.Minute)
		send([]uint8{47})
	}
	// A port scan while the limiter is full: named from the queue.
	spendMinute(e, &at, 1)
	for k := 0; k < 12; k++ {
		e.Process(synProbe(at, attacker, victim, uint16(1+k)))
		at += ms
	}
	drained := false
	for _, ev := range e.DrainPending(at + 60*sec) {
		drained = drained || ev.Src == attacker
	}
	if !drained {
		t.Fatal("the port scan was not drained; the test does not exercise its case")
	}
	at += 70 * sec
	at += uint64(6 * time.Minute)
	// Six of the seven come back: with 47 and the scan's TCP, eight
	// protocols, as many as were reported.
	if send(protos[:6]) {
		t.Fatal("protocols already reported were news again after a report from the queue")
	}
}

// TestADrainKeepsEveryKindItQueued: the drained event is rebuilt only if the
// state shows at least as much of every kind. A queued protocol scan whose
// protocols were forgotten while it waited, but which sent a few ports
// meanwhile, shows more in total and less in protocols: it keeps what it
// queued.
func TestADrainKeepsEveryKindItQueued(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := 3600 * sec
	spendMinute(e, &at, 0)
	for proto := 100; proto < 110; proto++ {
		e.Process(&Probe{TimeNs: at, Src: attacker, Dst: victim, Proto: uint8(proto)})
		at += ms
	}
	for m := 1; m <= 31; m++ {
		at = 3600*sec + uint64(m)*60*sec
		spendMinute(e, &at, byte(m))
		e.Process(&Probe{TimeNs: at, Src: attacker, Dst: victim, Proto: 100})
		at += ms
	}
	// A dozen UDP ports, too few to cross or to double the queued facts.
	for k := 0; k < 12; k++ {
		e.Process(udpProbe(at, attacker, victim, uint16(40000+k)))
		at += ms
	}
	var got *ScanEvent
	for m := 0; m < 3000 && got == nil; m++ {
		for _, ev := range e.DrainPending(at + uint64(m+1)*60*sec) {
			if ev.Src == attacker {
				got = ev
			}
		}
	}
	if got == nil || !got.IsProtocolScan || got.Protocols != 10 {
		t.Fatalf("the drained event is %v, want the 10-protocol scan it queued", got)
	}
}
