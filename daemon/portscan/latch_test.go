//go:build linux

package portscan

import (
	"net/netip"
	"testing"
	"time"
)

// TestLatchesAreReleasedWhenTheBucketEmpties pins that a conclusion drawn from
// traffic does not outlive the score that traffic produced.
//
// protoScan and icmpSweep cross without consulting the score at all, and
// hasTCPEvidence is the only gate before a block under the shipped policy.
// If nothing cleared any of them, they would last for ever. Measured that way
// over a simulated week: six ordinary packets from a peer terminating tunnels
// produced 2015 alerts at a score of zero throughout, and one forged packet
// with anomalous flags left a source blockable seven days later, also at zero.
func TestLatchesAreReleasedWhenTheBucketEmpties(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")

	t.Run("a protocol scan does not alert for ever", func(t *testing.T) {
		cfg := testConfig()
		cfg.ReportCooldown = 5 * time.Minute
		cfg.IdleExpiry = 30 * 24 * time.Hour // keep the entry, so the latch is what is tested
		e := newTestEngine(t, cfg, newFakeHost())

		peer := netip.MustParseAddr("203.0.113.40")
		alerts := 0
		for i, proto := range []uint8{47, 50, 51, 89, 103, 112} {
			if ev := e.Process(&Probe{
				TimeNs: sec + uint64(i)*ms, Src: peer, Dst: local, Proto: proto,
			}); ev != nil {
				alerts++
			}
		}
		if alerts == 0 {
			t.Fatal("the protocol scan was not reported at all; this test is not exercising its case")
		}

		// A week of silence, with the engine's own maintenance running.
		const week = 7 * 24 * 60
		for m := 1; m <= week; m++ {
			at := sec + uint64(m)*uint64(time.Minute)
			e.Expire(at)
			// One ordinary packet a minute from the same peer, on a protocol it
			// has already used: nothing new at all.
			if ev := e.Process(&Probe{
				TimeNs: at, Src: peer, Dst: local, Proto: 47,
			}); ev != nil {
				alerts++
			}
		}
		t.Logf("alerts over a simulated week: %d", alerts)
		if alerts > 2 {
			t.Fatalf("%d alerts over a week from six packets: protoScan is a latch"+
				" nothing releases", alerts)
		}
	})

	t.Run("evidence for blocking does not outlive the score", func(t *testing.T) {
		cfg := testConfig()
		cfg.IdleExpiry = 30 * 24 * time.Hour
		e := newTestEngine(t, cfg, newFakeHost())

		src := netip.MustParseAddr("203.0.113.41")
		// One forged packet nothing legitimate sends.
		e.Process(flagProbe(sec, src, local, 22, 0)) // NULL flags
		st, ok := e.table.lookup(src)
		if !ok || !st.hasTCPEvidence {
			t.Skip("the probe did not set the evidence bit; nothing to check")
		}

		// A week later, the score has long since leaked away.
		later := sec + uint64(7*24*time.Hour)
		e.Expire(later)
		e.Process(udpProbe(later, src, local, 9999))

		st, ok = e.table.lookup(src)
		if !ok {
			t.Skip("the entry was expired; the latch went with it")
		}
		if st.score == 0 && st.hasTCPEvidence {
			t.Fatal("a source with a score of zero is still block-eligible a week" +
				" after one forged packet")
		}
	})
}

// TestSlowProtocolAndICMPScansAreDetected pins that the facts that do not live
// in the bucket are not forgotten with it.
//
// Protocol probes and ICMP echo add nothing to the score, so for a source that
// sends nothing else the bucket is always empty. If the facts were cleared
// whenever the bucket was, on every decay step, five protocols would have to
// arrive within one DecayInterval, and nmap -sO at -T1 (one probe every 15 s)
// would never be detected, nor would -PE -PP -PM with the echo sent first.
// Kept apart from the bucket, they are detected at any rate.
func TestSlowProtocolAndICMPScansAreDetected(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	local6 := netip.MustParseAddr("2001:db8::1")
	protos := []uint8{2, 4, 41, 47, 50, 51, 89, 103, 112, 132, 136, 137}

	for _, gap := range []time.Duration{15 * time.Second, time.Minute, 5 * time.Minute} {
		e := newTestEngine(t, testConfig(), newFakeHost())
		src := netip.MustParseAddr("203.0.113.9")
		alerts := 0
		for i, p := range protos {
			if ev := e.Process(&Probe{TimeNs: sec + uint64(i)*uint64(gap),
				Src: src, Dst: local, Proto: p}); ev != nil {
				alerts++
			}
		}
		if alerts == 0 {
			t.Errorf("nmap -sO with one protocol every %v was never reported", gap)
		}

		for _, order := range [][]uint8{{8, 13, 17}, {8, 8, 13, 17}} {
			e := newTestEngine(t, testConfig(), newFakeHost())
			alerts := 0
			for i, typ := range order {
				if ev := e.Process(icmpProbe(sec+uint64(i)*uint64(gap), src, local, typ)); ev != nil {
					alerts++
				}
			}
			if alerts == 0 {
				t.Errorf("an ICMP sweep of types %v, one every %v, was never reported", order, gap)
			}
		}

		e = newTestEngine(t, testConfig(), newFakeHost())
		src6 := netip.MustParseAddr("2001:db8::66")
		alerts = 0
		for i, typ := range []uint8{128, 139} {
			if ev := e.Process(&Probe{TimeNs: sec + uint64(i)*uint64(gap), Src: src6,
				Dst: local6, Proto: ProtoICMPv6, DstPort: uint16(typ) << 8}); ev != nil {
				alerts++
			}
		}
		if alerts == 0 {
			t.Errorf("an ICMPv6 sweep, one type every %v, was never reported", gap)
		}
	}
}

// TestExpiredFactsComingBackAreNotNewsAgain is the other half: the facts do
// expire, and the same facts returning afterwards are not something new to say.
// A peer terminating tunnels sends the same handful of protocols all day.
func TestExpiredFactsComingBackAreNotNewsAgain(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	peer := netip.MustParseAddr("198.51.100.40")
	cfg := testConfig()
	e := newTestEngine(t, cfg, newFakeHost())

	protos := []uint8{47, 50, 51, 4, 41, 94}
	// The crossing is reported at the fifth protocol, and the sixth is news
	// once the cooldown lets it through; everything after the first hour is
	// repetition.
	alerts := 0
	// Two days, one packet a second, cycling over the same six protocols. Nothing
	// new arrives after the first six seconds, so the facts expire every
	// IdleExpiry and come straight back, unchanged.
	for i := 0; i < 2*86400; i++ {
		p := &Probe{TimeNs: sec + uint64(i)*uint64(time.Second), Src: peer, Dst: local,
			Proto: protos[i%len(protos)]}
		if ev := e.Process(p); ev != nil && i >= 3600 {
			alerts++
		}
	}
	if alerts > 0 {
		t.Fatalf("%d alerts over two days for a peer repeating the same six protocols:"+
			" facts that expire and come back unchanged are not news", alerts)
	}
}

// TestEvidenceIsForgottenWithTheScore: a SYN long decayed must not make a later
// UDP-only scan from the same address block-eligible.
func TestEvidenceIsForgottenWithTheScore(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	e.Process(synProbe(sec, attacker, victim, 22))
	later := sec + uint64(10*time.Minute)
	var ev *ScanEvent
	for i := 0; i < 60; i++ {
		if got := e.Process(udpProbe(later+uint64(i)*ms, attacker, victim, uint16(1+i))); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Fatal("the UDP scan was not reported; the test does not exercise its case")
	}
	if ev.BlockEligible {
		t.Fatal("a UDP-only scan became block-eligible on the strength of one SYN" +
			" whose score had long decayed to zero")
	}
}

// TestEvidenceExpiresWhenTheBucketNeverEmpties: a peer looping over more ports
// than the port ring holds keeps its score pinned, so the bucket never empties.
// Without an expiry of its own, one forged packet with anomalous flags from
// its address would leave it blockable for as long as it kept talking.
func TestEvidenceExpiresWhenTheBucketNeverEmpties(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	peer := netip.MustParseAddr("203.0.113.30")
	cfg := testConfig()
	e := newTestEngine(t, cfg, newFakeHost())

	e.Process(flagProbe(sec, peer, local, 80, TCPFin|TCPPsh|TCPUrg))
	if !e.LookupForBlock(peer).BlockEligible {
		t.Fatal("the anomalous packet gave no evidence; the test does not exercise its case")
	}
	window := uint64(cfg.ScoreThreshold) * uint64(cfg.DecayInterval)
	var last uint64
	for i := uint64(1); last <= sec+2*window; i++ {
		last = sec + i*uint64(time.Second)
		e.Process(udpProbe(last, peer, local, uint16(40000+i%128)))
	}
	if st, _ := e.table.lookup(peer); st.score == 0 {
		t.Fatal("the looping peer's bucket emptied; the test does not exercise its case")
	}
	if e.LookupForBlock(peer).BlockEligible {
		t.Fatalf("one anomalous packet %v ago still makes this peer blockable:"+
			" evidence must expire on its own clock", time.Duration(last-sec))
	}
}

// TestDecayKeepsTheRemainderOfAnInterval: decay advances by the whole intervals
// it consumed, keeping the remainder. Dropping it, a source sending every
// 0.9 x DecayInterval lost one point every two packets instead of one per
// interval, so slow ordinary traffic accumulated score it should have shed.
func TestDecayKeepsTheRemainderOfAnInterval(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(t, cfg, newFakeHost())
	local := netip.MustParseAddr("192.0.2.1")
	src := netip.MustParseAddr("203.0.113.61")

	// Ports 1-8 in quick succession: 96 points, under the threshold.
	for p := uint16(1); p <= 8; p++ {
		e.Process(synProbe(sec+uint64(p)*ms, src, local, p))
	}
	start := e.Score(src)
	if start == 0 {
		t.Fatal("no score to decay; the test does not exercise its case")
	}
	// Then the same port again every 0.9 intervals: repeats score nothing, so
	// only decay moves the score.
	step := uint64(cfg.DecayInterval) * 9 / 10
	last := sec + 8*ms
	for i := uint64(1); i <= 60; i++ {
		last = sec + 8*ms + i*step
		e.Process(synProbe(last, src, local, 1))
	}
	elapsed := last - (sec + ms) // decay is aligned on the first packet
	want := int64(start) - int64(elapsed/uint64(cfg.DecayInterval))
	if want < 0 {
		want = 0
	}
	if got := int64(e.Score(src)); got != want {
		t.Fatalf("score %d after %v of 0.9-interval repeats, want %d: the remainder of"+
			" each interval is being lost", got, time.Duration(elapsed), want)
	}
}

// TestNewPortsAreNewsAfterProtocolsExpire: the "something new to say" gate
// compares each kind of fact with its own baseline. With one baseline for all
// of them, a protocol scan reported earlier would keep the baseline high after
// its protocols expired, and a later SYN scan of up to 199 ports -- blockable,
// unlike the protocol scan -- would never be reported or proposed for
// blocking.
func TestNewPortsAreNewsAfterProtocolsExpire(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	src := netip.MustParseAddr("203.0.113.44")
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := sec
	// nmap -sO over 200 protocols, reported.
	reported := false
	for proto := 1; proto <= 200; proto++ {
		if p := uint8(proto); p == ProtoTCP || p == ProtoUDP || p == ProtoICMP || p == ProtoICMPv6 {
			continue
		}
		at += 10 * ms
		reported = e.Process(&Probe{TimeNs: at, Src: src, Dst: local, Proto: uint8(proto)}) != nil || reported
	}
	// Past the cooldown, one more packet so the rest of the protocols are
	// reported too, then the source stays alive with an old protocol every 20
	// minutes until its protocol facts expire.
	at += uint64(6 * time.Minute)
	e.Process(&Probe{TimeNs: at, Src: src, Dst: local, Proto: 201})
	for i := 0; i < 3; i++ {
		at += uint64(20 * time.Minute)
		e.Process(&Probe{TimeNs: at, Src: src, Dst: local, Proto: 47})
	}
	if !reported {
		t.Fatal("the protocol scan was not reported; the test does not exercise its case")
	}
	// Then a SYN scan of 150 ports.
	var ev *ScanEvent
	for port := 1; port <= 150 && ev == nil; port++ {
		at += 10 * ms
		ev = e.Process(synProbe(at, src, local, uint16(port)))
	}
	if ev == nil {
		t.Fatal("a 150-port SYN scan after an expired protocol scan was never reported:" +
			" old facts of another kind hid new ports")
	}
}

// TestMixedLoopingPeerIsNotNewsAgain: with a baseline per kind of fact, a peer
// repeating protocols, ports and ICMP types together must still fall silent:
// each kind only has news when it goes past its own highest count, and none
// ever does once the loop has been seen.
func TestMixedLoopingPeerIsNotNewsAgain(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	peer := netip.MustParseAddr("198.51.100.41")
	e := newTestEngine(t, testConfig(), newFakeHost())
	protos := []uint8{47, 50, 51, 4, 41, 94}
	alerts := 0
	for i := 0; i < 2*86400; i++ {
		at := sec + uint64(i)*uint64(time.Second)
		var p *Probe
		switch i % 3 {
		case 0:
			p = &Probe{TimeNs: at, Src: peer, Dst: local, Proto: protos[(i/3)%len(protos)]}
		case 1:
			p = udpProbe(at, peer, local, uint16(40000+(i/3)%10))
		default:
			p = icmpProbe(at, peer, local, []uint8{8, 13, 17}[(i/3)%3])
		}
		if ev := e.Process(p); ev != nil && i >= 3600 {
			alerts++
		}
	}
	if alerts > 0 {
		t.Fatalf("%d alerts over two days for a peer repeating the same protocols,"+
			" ports and ICMP types: facts that come back unchanged are not news", alerts)
	}
}

// TestNewICMPTypesAreNewsAfterAPortScan: a source reported for a port scan
// that then sends a query type it had not sent has something new to say. The
// echo request is the one query type that scores nothing and so never reaches
// the port count; once ICMP is a known protocol, only the ICMP-type baseline
// sees it.
func TestNewICMPTypesAreNewsAfterAPortScan(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	src := netip.MustParseAddr("203.0.113.45")
	// A short cooldown, so the score of the scan is still over the threshold
	// when it ends.
	cfg := testConfig()
	cfg.ReportCooldown = time.Second
	e := newTestEngine(t, cfg, newFakeHost())
	// A timestamp request first, so ICMP is already a known protocol and the
	// echo below is new only as a type.
	at := sec
	e.Process(icmpProbe(at, src, local, 13))
	var first *ScanEvent
	for port := 1; port <= 100 && first == nil; port++ {
		at += 10 * ms
		first = e.Process(synProbe(at, src, local, uint16(port)))
	}
	if first == nil {
		t.Fatal("the port scan was not reported; the test does not exercise its case")
	}
	// Past the cooldown, the ports it already sent are not news.
	at += uint64(2 * time.Second)
	for port := 1; port <= 3; port++ {
		at += 10 * ms
		if e.Process(synProbe(at, src, local, uint16(port))) != nil {
			t.Fatal("ports already reported were news again")
		}
	}
	at += 10 * ms
	if e.Process(icmpProbe(at, src, local, 8)) == nil {
		t.Fatal("an echo request after a reported port scan was not news:" +
			" the ICMP-type baseline is not consulted")
	}
}

// TestIdleFactsAreForgotten: the protocol and ICMP-type facts expire after
// IdleExpiry without a new one, even for a source that keeps sending. Only the
// other direction was tested -- that facts coming back are not news -- which a
// source that never forgets anything also passes; a tunnel peer or a
// monitoring system would stay "crossed" for as long as it is tracked.
func TestIdleFactsAreForgotten(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	src := netip.MustParseAddr("198.51.100.42")
	at := sec
	for _, proto := range []uint8{47, 50, 51, 4, 41, 94} {
		at += ms
		e.Process(&Probe{TimeNs: at, Src: src, Dst: victim, Proto: proto})
	}
	for _, typ := range []uint8{8, 13, 15, 17} {
		at += ms
		e.Process(icmpProbe(at, src, victim, typ))
	}
	state := func() (protoScan, icmpSweep bool, protos, types uint16) {
		shard := e.table.shardFor(src)
		shard.mu.Lock()
		defer shard.mu.Unlock()
		st, ok := shard.lookup(src)
		if !ok {
			t.Fatal("the source was forgotten altogether; the test does not exercise its case")
		}
		return st.protoScan, st.icmpSweep, st.protoCount, st.icmpTypeCount
	}
	if p, i, _, _ := state(); !p || !i {
		t.Fatalf("protoScan=%v icmpSweep=%v; the test does not exercise its case", p, i)
	}
	// Kept alive with a protocol it already sent, never anything new.
	for i := 0; i < 4; i++ {
		at += uint64(10 * time.Minute)
		e.Process(&Probe{TimeNs: at, Src: src, Dst: victim, Proto: 47})
	}
	if p, i, protos, types := state(); p || i || protos > 1 || types != 0 {
		t.Fatalf("after 40 minutes with nothing new: protoScan=%v icmpSweep=%v"+
			" protocols=%d ICMP types=%d, want all forgotten", p, i, protos, types)
	}
}

// TestABaselineNeverFalls: a report raises each kind's baseline to what the
// source has shown and never lowers it. After a protocol scan whose facts
// expired, a SYN scan is news and is reported; setting the baseline to what
// the source shows at that moment, instead of raising it, dropped the
// protocols' baseline to one, and the same protocols coming back were then
// reported again as if new.
func TestABaselineNeverFalls(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	src := netip.MustParseAddr("203.0.113.46")
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := sec
	protos := []uint8{47, 50, 51, 4, 41, 94, 132, 136}
	sendProtos := func(protos []uint8) (reported bool) {
		for _, proto := range protos {
			at += 10 * ms
			reported = e.Process(&Probe{TimeNs: at, Src: src, Dst: local, Proto: proto}) != nil || reported
		}
		return reported
	}
	if !sendProtos(protos) {
		t.Fatal("the protocol scan was not reported; the test does not exercise its case")
	}
	// Past the cooldown, all eight protocols are reported; then kept alive
	// with one of them until the protocol facts expire.
	at += uint64(6 * time.Minute)
	sendProtos(protos)
	for i := 0; i < 3; i++ {
		at += uint64(20 * time.Minute)
		e.Process(&Probe{TimeNs: at, Src: src, Dst: local, Proto: 47})
	}
	var syn *ScanEvent
	for port := 1; port <= 60 && syn == nil; port++ {
		at += 10 * ms
		syn = e.Process(synProbe(at, src, local, uint16(port)))
	}
	if syn == nil {
		t.Fatal("the SYN scan was not reported; the test does not exercise its case")
	}
	// Seven of the eight come back. The SYN scan's TCP is a protocol seen
	// too, so the source shows eight again: no more than it was reported for.
	at += uint64(6 * time.Minute)
	if sendProtos(protos[:7]) {
		t.Fatal("the protocols of a scan already reported were reported again")
	}
}

// TestAProtocolScanAfterAPortReportIsNews: a source reported for a port scan
// that then runs nmap -sO has something new to say.
func TestAProtocolScanAfterAPortReportIsNews(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	src := netip.MustParseAddr("203.0.113.47")
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := sec
	var ev *ScanEvent
	for port := 1; port <= 150 && ev == nil; port++ {
		at += 10 * ms
		ev = e.Process(synProbe(at, src, local, uint16(port)))
	}
	if ev == nil {
		t.Fatal("the port scan was not reported; the test does not exercise its case")
	}
	at += uint64(6 * time.Minute)
	reported := false
	for _, proto := range []uint8{47, 50, 51, 4, 41, 94, 132, 136} {
		at += 10 * ms
		reported = e.Process(&Probe{TimeNs: at, Src: src, Dst: local, Proto: proto}) != nil || reported
	}
	if !reported {
		t.Fatal("a protocol scan after a reported port scan was never reported")
	}
}

// TestICMPTypesComingBackAfterAProtocolReportAreNotNews: the ICMP-type
// baseline only goes up too. A sweep reported, its types forgotten, then a
// protocol scan reported: the same types coming back are not news.
func TestICMPTypesComingBackAfterAProtocolReportAreNotNews(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	src := netip.MustParseAddr("203.0.113.48")
	e := newTestEngine(t, testConfig(), newFakeHost())
	at := sec
	sweep := func() (reported bool) {
		for _, typ := range []uint8{8, 13, 15, 17} {
			at += 10 * ms
			reported = e.Process(icmpProbe(at, src, local, typ)) != nil || reported
		}
		return reported
	}
	if !sweep() {
		t.Fatal("the ICMP sweep was not reported; the test does not exercise its case")
	}
	// Kept alive with a protocol until the ICMP types are forgotten.
	for i := 0; i < 3; i++ {
		at += uint64(20 * time.Minute)
		e.Process(&Probe{TimeNs: at, Src: src, Dst: local, Proto: 47})
	}
	// The protocol scan includes ICMP itself, one echo request, so the sweep
	// coming back brings no new protocol, only its types.
	at += 10 * ms
	reported := e.Process(icmpProbe(at, src, local, 8)) != nil
	for _, proto := range []uint8{50, 51, 4, 41, 94, 132} {
		at += 10 * ms
		reported = e.Process(&Probe{TimeNs: at, Src: src, Dst: local, Proto: proto}) != nil || reported
	}
	if !reported {
		t.Fatal("the protocol scan was not reported; the test does not exercise its case")
	}
	// Past the cooldown, a protocol already sent: the protocols that arrived
	// after the report are reported too, so all of them are behind us.
	at += uint64(6 * time.Minute)
	e.Process(&Probe{TimeNs: at, Src: src, Dst: local, Proto: 50})
	at += uint64(6 * time.Minute)
	if sweep() {
		t.Fatal("the ICMP types of a sweep already reported were reported again")
	}
}
