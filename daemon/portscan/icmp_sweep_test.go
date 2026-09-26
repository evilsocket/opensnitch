package portscan

import (
	"net/netip"
	"testing"
)

// icmpProbe builds an ICMP or ICMPv6 probe of a given message type.
//
// Type and code live in DstPort packed as type<<8|code, which is the engine's
// own convention (see Probe.ICMPType); building the field by hand here rather
// than through a setter is deliberate, so that a change to that packing breaks
// this test instead of silently reinterpreting it.
func icmpProbe(tNs uint64, src, dst netip.Addr, typ uint8) *Probe {
	proto := ProtoICMP
	if src.Is6() {
		proto = ProtoICMPv6
	}
	return &Probe{
		TimeNs: tNs, Src: src, Dst: dst,
		Proto: proto, DstPort: uint16(typ) << 8,
	}
}

// feedICMPTypes sends one probe per type, 1 ms apart, and returns the first
// event the engine emitted.
func feedICMPTypes(e *Engine, src, dst netip.Addr, types []uint8) *ScanEvent {
	var first *ScanEvent
	for i, typ := range types {
		if ev := e.Process(icmpProbe(sec+uint64(i)*ms, src, dst, typ)); ev != nil && first == nil {
			first = ev
		}
	}
	return first
}

// TestICMPSweepCountsOnlyQueryTypes pins which ICMP message types may feed the
// distinct-type counter behind icmpSweep.
//
// The counter originally accepted all 256 values. Three ICMP packets of any
// types whatsoever produced an "ICMP host sweep" alert naming the source, with
// a score of 0 and no ports -- an accusation the user had no way to check,
// against an address that is trivially forged on a connectionless probe.
//
// The false-positive half mattered more than the forgery half. The three types
// an ordinary intermediate router sends are Time Exceeded, Destination
// Unreachable and Echo Reply; over IPv6, where PMTUD is mandatory, they are
// Packet Too Big, Time Exceeded and Echo Reply. One traceroute was enough.
func TestICMPSweepCountsOnlyQueryTypes(t *testing.T) {
	cases := []struct {
		name  string
		src   netip.Addr
		dst   netip.Addr
		types []uint8
		sweep bool
		why   string
	}{
		{
			name: "traceroute and PMTUD from an intermediate router", src: attacker, dst: victim,
			types: []uint8{0, 3, 11}, sweep: false,
			why: "Echo Reply, Destination Unreachable and Time Exceeded are what a router on our own path sends",
		},
		{
			name: "ping reply plus an unreachable", src: attacker, dst: victim,
			types: []uint8{8, 0, 3}, sweep: false,
			why: "only Echo Request is a query here, so the distinct-query count is 1",
		},
		{
			name: "unassigned types", src: attacker, dst: victim,
			types: []uint8{200, 201, 202}, sweep: false,
			why: "types that mean nothing must not be evidence of anything",
		},
		{
			name: "IPv6 traceroute6 through one router", src: attacker6, dst: victim6,
			types: []uint8{2, 3, 129}, sweep: false,
			why: "Packet Too Big, Time Exceeded and Echo Reply arrive from a single router during mandatory PMTUD",
		},
		{
			name: "nmap -PE -PP -PM", src: attacker, dst: victim,
			types: []uint8{icmpv4Echo, icmpv4Timestamp, icmpv4AddressMask}, sweep: true,
			why: "the signature this detector exists for must still cross",
		},
		{
			name: "the three dead IPv4 query types", src: attacker, dst: victim,
			types: []uint8{icmpv4Timestamp, icmpv4Information, icmpv4AddressMask}, sweep: true,
			why: "nothing has used these in decades except a scanner",
		},
		{
			name: "one query type repeated", src: attacker, dst: victim,
			types: []uint8{icmpv4Echo, icmpv4Echo, icmpv4Echo, icmpv4Echo}, sweep: false,
			why: "a monitoring system pinging all day is one type, whatever the rate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, testConfig(), newFakeHost())
			ev := feedICMPTypes(e, tc.src, tc.dst, tc.types)

			got := ev != nil && ev.Method == MethodICMPSweep
			if got != tc.sweep {
				t.Fatalf("icmp-sweep reported = %v, want %v (types %v): %s",
					got, tc.sweep, tc.types, tc.why)
			}
			if !tc.sweep && ev != nil {
				t.Fatalf("no event expected at all for types %v, got method %v", tc.types, ev.Method)
			}
		})
	}
}

// TestICMPSweepRespectsItsSwitch pins that DetectICMPSweep turns the detector
// off without touching the others.
//
// Before it existed the only way to silence ICMP detection was to set
// ICMPSweepMinTypes to 256, which nothing documented.
func TestICMPSweepRespectsItsSwitch(t *testing.T) {
	cfg := testConfig()
	cfg.DetectICMPSweep = false
	e := newTestEngine(t, cfg, newFakeHost())

	if ev := feedICMPTypes(e, attacker, victim,
		[]uint8{icmpv4Echo, icmpv4Timestamp, icmpv4AddressMask}); ev != nil {
		t.Fatalf("DetectICMPSweep is false, yet an event was reported: %v", ev.Method)
	}

	// TCP detection is untouched by that switch. Eleven system ports rather
	// than the nine that would just suffice: the port filter is randomly seeded
	// and has false positives, so a margin narrower than one port's worth makes
	// this test fail about once in a hundred runs. See crossOnce.
	if ev := feedPorts(e, 10*sec, ms, attacker6, victim6,
		[]uint16{21, 22, 23, 25, 110, 143, 445, 993, 995, 587, 636}, synProbe); ev == nil {
		t.Fatal("turning off DetectICMPSweep also silenced TCP detection")
	}
}

// TestDefaultConfigEnablesICMPSweep guards the default, since the detector is
// only useful if it is on.
func TestDefaultConfigEnablesICMPSweep(t *testing.T) {
	if !DefaultConfig().DetectICMPSweep {
		t.Fatal("DefaultConfig().DetectICMPSweep is false")
	}
}

// TestICMPScoringIsPerAddressFamily pins that the SCORING path reads the
// message type per family, as the distinct-type counter does.
//
// The first version of the family rule was applied only to the counter. The
// scoring switch still pooled both families, so types 13, 15 and 17 -- which
// are unassigned in ICMPv6 -- and type 139 -- unassigned in ICMPv4 -- scored 40
// each. Three forged packets reached 120 against a threshold of 100 and named
// any chosen address in an alert, which is precisely the cost the family rule
// was introduced to remove, moved from one path to the other.
func TestICMPScoringIsPerAddressFamily(t *testing.T) {
	cases := []struct {
		name      string
		src, dst  netip.Addr
		types     []uint8
		wantEvent bool
	}{
		{
			name: "IPv4 types over ICMPv6", src: attacker6, dst: victim6,
			types:     []uint8{icmpv4Timestamp, icmpv4Information, icmpv4AddressMask},
			wantEvent: false,
		},
		{
			// 139 is unassigned in ICMPv4, so it scores nothing and counts
			// nothing. What is left is two real IPv4 query types: 80 points
			// against a threshold of 100, and two distinct types against a
			// sweep minimum of three. Neither path crosses, which is the whole
			// point -- before the family rule reached the scoring switch, this
			// exact triple scored 120 and named the source.
			name: "IPv6 type over ICMPv4", src: attacker, dst: victim,
			types:     []uint8{icmpv6NodeInfoQuery, icmpv4Timestamp, icmpv4Information},
			wantEvent: false,
		},
		{
			name: "the three IPv4 query types, over IPv4", src: attacker, dst: victim,
			types:     []uint8{icmpv4Timestamp, icmpv4Information, icmpv4AddressMask},
			wantEvent: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, testConfig(), newFakeHost())
			ev := feedICMPTypes(e, tc.src, tc.dst, tc.types)
			if (ev != nil) != tc.wantEvent {
				t.Fatalf("event = %v, want %v for types %v over %v",
					ev != nil, tc.wantEvent, tc.types, tc.src)
			}
			if ev != nil && ev.Method == MethodUnknown {
				t.Fatalf("an ICMP source crossed with method %q: an alert naming an"+
					" address with no technique and no ports is unverifiable", ev.Method)
			}
		})
	}
}

// TestICMPSweepIsReachableOverIPv6 pins that the ICMPv6 detector can fire at all.
//
// ICMPv6 has two query types a scanner sends and ordinary traffic does not, so
// with ICMPSweepMinTypes at its default of 3 the counter could never reach the
// threshold: sending all 256 ICMPv6 types from one source stopped at 2. The
// detector was able to fire only on unassigned types and unable to fire on
// anything real -- the inverse of the property wanted.
func TestICMPSweepIsReachableOverIPv6(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	ev := feedICMPTypes(e, attacker6, victim6, []uint8{icmpv6Echo, icmpv6NodeInfoQuery})
	if ev == nil {
		t.Fatal("echo request plus a Node Information Query from one IPv6 source" +
			" reported nothing; the ICMPv6 sweep detector cannot fire")
	}
	if ev.Method != MethodICMPSweep {
		t.Fatalf("method = %v, want icmp-sweep", ev.Method)
	}

	// And it still takes both: a single type is not a sweep in either family.
	e2 := newTestEngine(t, testConfig(), newFakeHost())
	for i := 0; i < 20; i++ {
		if ev := e2.Process(icmpProbe(sec+uint64(i)*ms, attacker6, victim6, icmpv6Echo)); ev != nil {
			t.Fatalf("twenty ICMPv6 echo requests reported %v: a ping is not a sweep", ev.Method)
		}
	}
}

// TestICMPSweepSwitchSilencesScoringToo pins that DetectICMPSweep turns ICMP
// detection off, rather than only its distinct-type counter.
//
// Gating the counter alone left three scored types reaching 120 with the switch
// off -- and reporting method "unknown", because the flag that would have named
// the technique was the one thing that had been disabled.
func TestICMPSweepSwitchSilencesScoringToo(t *testing.T) {
	cfg := testConfig()
	cfg.DetectICMPSweep = false
	e := newTestEngine(t, cfg, newFakeHost())

	if ev := feedICMPTypes(e, attacker, victim,
		[]uint8{icmpv4Timestamp, icmpv4Information, icmpv4AddressMask}); ev != nil {
		t.Fatalf("DetectICMPSweep is false, yet ICMP scoring reported %v with score %d",
			ev.Method, ev.Score)
	}
}

// TestICMPSweepReportsNoPorts pins that an ICMP sweep does not publish message
// types as if they were ports.
//
// Probe.DstPort carries type<<8|code for ICMP, which is what lets a source be
// scored once per distinct type rather than once per packet. The same value was
// then recorded as a port, so an nmap -PP -PM sweep reached the user as "3 ports
// probed between 3328 and 4352" with a sample of [3328 3840 4352] -- types 13,
// 15 and 17 shifted left by eight -- when not one port had been touched. The
// protocol definition of those fields says every field states only what the
// observed packets establish.
func TestICMPSweepReportsNoPorts(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	ev := feedICMPTypes(e, attacker, victim,
		[]uint8{icmpv4Timestamp, icmpv4Information, icmpv4AddressMask})
	if ev == nil {
		t.Fatal("the sweep was not reported")
	}
	if ev.Method != MethodICMPSweep {
		t.Fatalf("method = %v, want icmp-sweep", ev.Method)
	}
	if ev.DistinctPorts != 0 || ev.MinPort != 0 || ev.MaxPort != 0 || len(ev.SamplePorts) != 0 {
		t.Fatalf("an ICMP-only source reported ports: distinct=%d min=%d max=%d sample=%v",
			ev.DistinctPorts, ev.MinPort, ev.MaxPort, ev.SamplePorts)
	}
	// The scoring still worked, so the deduplication the packed field exists for
	// is intact.
	if ev.Score == 0 {
		t.Fatal("the sweep scored nothing; deduplication by message type is broken")
	}
}

// TestAnICMPOnlySweepIsNotBlockEligible: an ICMP source costs nothing to forge,
// so a reconnaissance probe is not evidence. Nothing tested it: marking the
// icmp-recon class as evidence left the suite green, and a forged -PP -PM
// sweep could get a third party blocked under the auto policy.
func TestAnICMPOnlySweepIsNotBlockEligible(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	ev := feedICMPTypes(e, attacker, victim, []uint8{8, 13, 15, 17})
	if ev == nil {
		t.Fatal("the ICMP sweep was not reported; the test does not exercise its case")
	}
	if ev.HasTCPEvidence || ev.BlockEligible {
		t.Fatalf("an ICMP-only sweep is block-eligible (evidence=%v eligible=%v):"+
			" a forged ICMP source can be blocked", ev.HasTCPEvidence, ev.BlockEligible)
	}
}

// TestICMPCodesDoNotMultiplyTheScore: an ICMP probe is scored once per
// message type, as documented. The code travels beside the type and was part
// of the deduplication key, so three timestamp requests with codes 0, 1 and 2
// scored three times and raised an alert in anyone's name.
func TestICMPCodesDoNotMultiplyTheScore(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	src := netip.MustParseAddr("203.0.113.77")
	var ev *ScanEvent
	for code := uint16(0); code < 3; code++ {
		p := icmpProbe(sec+uint64(code)*ms, src, victim, 13)
		p.DstPort |= code
		if got := e.Process(p); got != nil {
			ev = got
		}
	}
	if ev != nil || e.Score(src) != weightICMPRecon {
		t.Fatalf("three codes of one ICMP type scored %d (alert: %v), want one type's %d",
			e.Score(src), ev != nil, weightICMPRecon)
	}
}

// TestICMPv6CodesDoNotMultiplyTheScore: the same rule in IPv6, where a Node
// Information Query (`ping -N`) legitimately uses codes 0, 1 and 2.
func TestICMPv6CodesDoNotMultiplyTheScore(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	src := netip.MustParseAddr("2001:db8::77")
	for code := uint16(0); code < 3; code++ {
		p := icmpProbe(sec+uint64(code)*ms, src, victim6, icmpv6NodeInfoQuery)
		p.DstPort |= code
		e.Process(p)
	}
	if got := e.Score(src); got != weightICMPRecon {
		t.Fatalf("three codes of one ICMPv6 type scored %d, want one type's %d", got, weightICMPRecon)
	}
}
