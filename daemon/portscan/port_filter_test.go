//go:build linux

package portscan

import (
	"net/netip"
	"testing"
	"time"
)

// TestLoopingPeerIsNotRescored pins that a source whose working set exceeds the
// filter's generation is not scored again on every round.
//
// addPort remembers the last portFilterGeneration ports it accepted, so a
// source that cycles over more ports than that has its own working set look
// new again as it comes round. The boundary is a cliff, not a gradient:
// measured over 500 rounds, 63 distinct ports gave 0.2% of packets accepted
// and 65 gave 98.5%. Without the evidence gate in shouldReport, a peer sending
// one datagram a second to 64 distinct ports would go from 1 alert a day to
// 288, with the score pinned at its ceiling, permanently and with no attacker
// involved.
func TestLoopingPeerIsNotRescored(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")

	for _, ports := range []int{32, 63, 64, 65, 80, 128} {
		t.Run("", func(t *testing.T) {
			cfg := testConfig()
			cfg.ReportCooldown = 5 * time.Minute
			e := newTestEngine(t, cfg, newFakeHost())

			peer := netip.MustParseAddr("203.0.113.30")
			alerts := 0
			// A day of one datagram a second, cycling over `ports` ports.
			const day = 86400
			for i := 0; i < day; i++ {
				p := udpProbe(sec+uint64(i)*uint64(time.Second),
					peer, local, uint16(40000+i%ports))
				if ev := e.Process(p); ev != nil {
					alerts++
				}
			}
			st, _ := e.table.lookup(peer)
			// The figure the user is shown, not the raw internal counter: the
			// port ring re-accepts a working set larger than one generation,
			// so distinctPorts climbs without limit for a looping source, and
			// reportedPortCount clamps it to the span actually observed -- which
			// is exact and cannot exceed what the range could hold.
			shown := reportedPortCount(&st)
			t.Logf("%3d ports cycled over a day: %d alert(s), score %d, reported %d ports",
				ports, alerts, st.score, shown)

			if shown > uint32(ports) {
				t.Errorf("%d ports cycled but the alert claims %d: the reported"+
					" figure is not bounded by what was observed", ports, shown)
			}
			// A peer that changes nothing must not be named again and again.
			// Named on every cooldown for ever, it would appear 288 times a
			// day at the shipped five minutes.
			if alerts > 2 {
				t.Errorf("%d alerts in a day for a peer cycling over %d ports:"+
					" the cooldown is a timer, not a reason to re-report",
					alerts, ports)
			}
		})
	}
}

// TestFilterStillClearsForAWalkingScanner pins the property the generation
// mechanism exists for: a scanner walking new ports must keep being scored, so
// that filling the filter cannot become a way to switch scoring off.
func TestFilterStillClearsForAWalkingScanner(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	local := netip.MustParseAddr("192.0.2.1")

	// Far more than the filter could hold at once.
	const walked = 4000
	accepted := 0
	for i := 0; i < walked; i++ {
		p := udpProbe(sec+uint64(i)*ms, attacker, local, uint16(1024+i))
		e.Process(p)
	}
	st, _ := e.table.lookup(attacker)
	accepted = int(st.distinctPorts)
	t.Logf("a scanner walking %d new ports was scored for %d of them (%d generations)",
		walked, accepted, st.generations)

	if accepted < walked/2 {
		t.Fatalf("only %d of %d walked ports were counted: filling the filter has"+
			" become a way to stop being scored", accepted, walked)
	}
}
