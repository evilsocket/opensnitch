package portscan

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// test harness
// ---------------------------------------------------------------------------

// fakeHost is a controllable HostInfo. Every predicate defaults to the value a
// plain, non-exempt, non-listening host would return, so a test only states
// what it actually cares about.
type fakeHost struct {
	localUnicast map[netip.Addr]bool
	listening    map[string]bool
	connections  map[string]bool
	onLink       map[netip.Addr]bool
	exempt       map[netip.Addr]bool
	// allLocal makes every destination count as ours, which is what most
	// tests want.
	allLocal bool
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		localUnicast: map[netip.Addr]bool{},
		listening:    map[string]bool{},
		connections:  map[string]bool{},
		onLink:       map[netip.Addr]bool{},
		exempt:       map[netip.Addr]bool{},
		allLocal:     true,
	}
}

func portKey(proto uint8, port uint16) string { return fmt.Sprintf("%d/%d", proto, port) }

func connKey(p *Probe) string {
	return fmt.Sprintf("%d|%s:%d|%s:%d", p.Proto, p.Src, p.SrcPort, p.Dst, p.DstPort)
}

func (h *fakeHost) IsLocalUnicast(a netip.Addr) bool {
	if h.allLocal {
		return !a.IsMulticast()
	}
	return h.localUnicast[a]
}
func (h *fakeHost) IsListening(proto uint8, port uint16) bool {
	return h.listening[portKey(proto, port)]
}
func (h *fakeHost) HasConnection(p *Probe) bool { return h.connections[connKey(p)] }
func (h *fakeHost) IsOnLink(a netip.Addr) bool  { return h.onLink[a] }
func (h *fakeHost) IsExempt(a netip.Addr) bool  { return h.exempt[a] }

const (
	sec = uint64(time.Second)
	ms  = uint64(time.Millisecond)
)

var (
	attacker  = netip.MustParseAddr("192.0.2.66")
	attacker6 = netip.MustParseAddr("2001:db8::66")
	victim    = netip.MustParseAddr("192.0.2.1")
	victim6   = netip.MustParseAddr("2001:db8::1")
)

// testConfig returns a configuration with the startup grace removed, since
// nearly every test wants to feed probes immediately. TestStartupGrace covers
// the grace period itself.
func testConfig() Config {
	c := DefaultConfig()
	c.Enabled = true
	c.StartupGrace = 0
	return c
}

func newTestEngine(t *testing.T, cfg Config, h HostInfo) *Engine {
	t.Helper()
	e, err := NewEngine(cfg, h, 0)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// synProbe builds a plain TCP SYN probe, with the flag octet marked as
// actually read -- which is what a complete, unfragmented packet yields.
func synProbe(tNs uint64, src, dst netip.Addr, port uint16) *Probe {
	return &Probe{
		TimeNs: tNs, Src: src, Dst: dst,
		Proto: ProtoTCP, TCPFlags: TCPSyn, TCPFlagsValid: true,
		SrcPort: 40000, DstPort: port,
	}
}

func flagProbe(tNs uint64, src, dst netip.Addr, port uint16, flags uint8) *Probe {
	p := synProbe(tNs, src, dst, port)
	p.TCPFlags = flags
	return p
}

func udpProbe(tNs uint64, src, dst netip.Addr, port uint16) *Probe {
	return &Probe{
		TimeNs: tNs, Src: src, Dst: dst,
		Proto: ProtoUDP, SrcPort: 40000, DstPort: port,
	}
}

// feedPorts sends one probe per port, spaced by gapNs, and returns the first
// event emitted (or nil).
func feedPorts(e *Engine, startNs, gapNs uint64, src, dst netip.Addr, ports []uint16, mk func(uint64, netip.Addr, netip.Addr, uint16) *Probe) *ScanEvent {
	var first *ScanEvent
	for i, port := range ports {
		ev := e.Process(mk(startNs+uint64(i)*gapNs, src, dst, port))
		if ev != nil && first == nil {
			first = ev
		}
	}
	return first
}

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

func TestDefaultConfigIsValid(t *testing.T) {
	c := DefaultConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("DefaultConfig() is not valid: %v", err)
	}
}

// TestConfigValidateRejectsOutOfRange checks that bad values are refused
// rather than silently clamped. scanlogd's off-by-one on SCAN_MAX_COUNT was
// harmless while the thresholds were compile-time constants and only became
// reachable in "other projects reusing this code [that] could make these
// settings runtime (mis)configurable" (scanlogd commit 66f425d).
func TestConfigValidateRejectsOutOfRange(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"zero threshold", func(c *Config) { c.ScoreThreshold = 0 }},
		{"absurd threshold", func(c *Config) { c.ScoreThreshold = 1 << 21 }},
		{"zero decay", func(c *Config) { c.DecayInterval = 0 }},
		{"negative decay", func(c *Config) { c.DecayInterval = -time.Second }},
		{"tiny table", func(c *Config) { c.MaxSources = 8 }},
		{"absurd table", func(c *Config) { c.MaxSources = 1 << 21 }},
		{"zero idle expiry", func(c *Config) { c.IdleExpiry = 0 }},
		{"negative grace", func(c *Config) { c.StartupGrace = -time.Second }},
		{"proto threshold too low", func(c *Config) { c.ProtoScanMinProtocols = 1 }},
		{"zero alerts", func(c *Config) { c.AlertsPerMinute = 0 }},
		{"unknown policy", func(c *Config) { c.Block.Policy = "sometimes" }},
		{"zero block duration", func(c *Config) { c.Block.Duration = 0 }},
		{"zero max blocked", func(c *Config) { c.Block.MaxBlockedSources = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			tc.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate() accepted an invalid config (%s)", tc.name)
			}
			if _, err := NewEngine(c, newFakeHost(), 0); err == nil {
				t.Fatalf("NewEngine() accepted an invalid config (%s)", tc.name)
			}
		})
	}
}

// TestSlowestDetectableScan pins the relationship between the decay interval
// and the slowest scan the engine reports within its stated horizon.
//
// The figure decides which nmap timing templates are covered, and the
// documentation and coverage report are generated from it, so it is asserted
// rather than described in prose.
//
// The figure is not perProbeWeight*DecayInterval minus one interval (110s),
// "the slowest delay that still makes progress": that is a supremum of delays
// at which the score grows at all, not a delay at which anything is detected.
// At 110s the threshold is reached after about 3 h 25, by which time the
// scanner has finished and left.
func TestSlowestDetectableScan(t *testing.T) {
	c := DefaultConfig() // DecayInterval = 10s, threshold 100
	// A SYN to a closed system port is worth 4*3 = 12 points.
	w := ProbeWeight(PortSystem, multSynClosed)
	if w != 12 {
		t.Fatalf("system-port SYN weight = %d, want 12", w)
	}

	got := c.SlowestDetectableScan(w)

	// Whatever it returns, it must be honest: a scan at that delay crosses
	// within the horizon, and one measurably slower does not.
	if d := c.timeToCross(w, got); d > detectionHorizon {
		t.Fatalf("SlowestDetectableScan reports %v, but a scan at that delay takes %v"+
			" to cross, beyond the %v horizon", got, d, detectionHorizon)
	}
	if d := c.timeToCross(w, got+time.Second); d <= detectionHorizon {
		t.Fatalf("a scan one second slower than the reported %v still crosses in %v:"+
			" the boundary is not where it says", got, d)
	}

	// nmap -T1 waits 15s between probes: covered.
	if got <= 15*time.Second {
		t.Errorf("configuration cannot detect nmap -T1 (15s between probes); slowest = %v", got)
	}
	// nmap -T0 waits 300s: not covered, and that must stay explicit.
	if got >= 300*time.Second {
		t.Errorf("configuration unexpectedly claims to detect nmap -T0 (300s between probes); slowest = %v", got)
	}

	// The cases that genuinely have no answer report none.
	//
	// "A probe worth one point can never outrun its own decay" is not one of
	// them: at any weight there is always a delay short enough to accumulate,
	// and a function that returned 0 there would do so only because it
	// compared against one decay interval rather than computing anything.
	if d := c.SlowestDetectableScan(0); d != 0 {
		t.Errorf("SlowestDetectableScan(0) = %v, want 0: a weightless probe scores nothing", d)
	}
	if d := c.SlowestDetectableScanWithin(w, 0); d != 0 {
		t.Errorf("a zero horizon reported %v, want 0", d)
	}
	noDecay := c
	noDecay.DecayInterval = 0
	if d := noDecay.SlowestDetectableScan(w); d != 0 {
		t.Errorf("SlowestDetectableScan with no decay interval = %v, want 0", d)
	}
}

func TestClassifyPort(t *testing.T) {
	cases := []struct {
		port uint16
		want PortClass
	}{
		{1, PortSystem}, {22, PortSystem}, {1023, PortSystem},
		{1024, PortRegistered}, {8080, PortRegistered}, {49151, PortRegistered},
		{49152, PortDynamic}, {65535, PortDynamic},
	}
	for _, tc := range cases {
		if got := ClassifyPort(tc.port); got != tc.want {
			t.Errorf("ClassifyPort(%d) = %v, want %v", tc.port, got, tc.want)
		}
	}
	// Port 0 is in the system range by arithmetic; it is never a real
	// destination but must not panic or classify as dynamic.
	if got := ClassifyPort(0); got != PortSystem {
		t.Errorf("ClassifyPort(0) = %v, want %v", got, PortSystem)
	}
}

// ---------------------------------------------------------------------------
// scan method naming
// ---------------------------------------------------------------------------

// TestScanMethodNaming feeds each nmap technique's exact flag combination and
// checks the reported method. The expectations come from the nmap manual's
// "Port Scanning Techniques" page, not from this package's own tables.
func TestScanMethodNaming(t *testing.T) {
	cases := []struct {
		name  string
		flags uint8
		want  ScanMethod
	}{
		{"-sS/-sT SYN", TCPSyn, MethodSYN},
		{"-sF FIN", TCPFin, MethodFIN},
		{"-sN NULL", 0, MethodNULL},
		{"-sX Xmas (FIN|PSH|URG)", TCPFin | TCPPsh | TCPUrg, MethodXmas},
		{"-sM Maimon (FIN|ACK)", TCPFin | TCPAck, MethodMaimon},
		{"-sA/-sW ACK", TCPAck, MethodACK},
		{"SYN|FIN", TCPSyn | TCPFin, MethodSYNFIN},
		{"all flags", TCPSyn | TCPRst | TCPAck | TCPFin | TCPPsh | TCPUrg, MethodFullXmas},
		{"-O fingerprint (URG|PSH|SYN|FIN)", TCPUrg | TCPPsh | TCPSyn | TCPFin, MethodOSFingerprint},
		{"--scanflags PSH", TCPPsh, MethodCustomFlags},
		{"--scanflags CWR|ECE", TCPCwr | TCPEce, MethodCustomFlags},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, testConfig(), newFakeHost())
			ports := make([]uint16, 40)
			for i := range ports {
				ports[i] = uint16(20 + i)
			}
			ev := feedPorts(e, sec, ms, attacker, victim, ports,
				func(tn uint64, s, d netip.Addr, p uint16) *Probe {
					return flagProbe(tn, s, d, p, tc.flags)
				})
			if ev == nil {
				t.Fatalf("no scan detected for %s", tc.name)
			}
			if ev.Method != tc.want {
				t.Errorf("Method = %v (%s), want %v", ev.Method, ev.MethodDetail, tc.want)
			}
		})
	}
}

// TestACKAndWindowScanAreNotDistinguished pins the honesty requirement: nmap
// -sA and -sW put identical bytes on the wire and differ only in how the
// scanner reads the RST it gets back. Claiming to tell them apart would be a
// fabrication, so both must map to the same method and the description must
// name both options.
func TestACKAndWindowScanAreNotDistinguished(t *testing.T) {
	if got := methodFromFlags(flagsACK); got != MethodACK {
		t.Fatalf("bare ACK maps to %v, want MethodACK", got)
	}
	d := MethodACK.Description()
	for _, want := range []string{"-sA", "-sW"} {
		if !contains(d, want) {
			t.Errorf("MethodACK.Description() = %q, must mention %s", d, want)
		}
	}
}

// TestMixedFlagsNotGuessed checks that a source varying its flag combination
// is reported as mixed rather than as whichever technique happened to be seen
// last. nmap --scanflags and multi-mode scanners land here legitimately.
func TestMixedFlagsNotGuessed(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	var ev *ScanEvent
	for i := 0; i < 40; i++ {
		flags := TCPSyn
		if i%2 == 1 {
			flags = TCPFin
		}
		if got := e.Process(flagProbe(sec+uint64(i)*ms, attacker, victim, uint16(100+i), flags)); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Fatal("no scan detected")
	}
	if ev.Method != MethodMixedFlags {
		t.Errorf("Method = %v, want MethodMixedFlags", ev.Method)
	}
	// The '?' characters in the summary are what record that the bits varied.
	if !contains(ev.FlagsSummary, "?") {
		t.Errorf("FlagsSummary = %q, expected varying bits marked with '?'", ev.FlagsSummary)
	}
}

// TestFlagsStringMatchesScanlogd checks the rendering against the semantics
// documented in scanlogd's own man page: uppercase when a bit was always set,
// lowercase when always clear, '?' when it changed.
func TestFlagsStringMatchesScanlogd(t *testing.T) {
	cases := []struct {
		or, and uint8
		want    string
	}{
		{TCPSyn, TCPSyn, "fSrpauec"},
		{TCPFin, TCPFin, "Fsrpauec"},
		{0, 0, "fsrpauec"},
		{TCPFin | TCPPsh | TCPUrg, TCPFin | TCPPsh | TCPUrg, "FsrPaUec"},
		{TCPSyn | TCPFin, TCPSyn, "?Srpauec"},
		{0xff, 0xff, "FSRPAUEC"},
	}
	for _, tc := range cases {
		if got := FlagsString(tc.or, tc.and); got != tc.want {
			t.Errorf("FlagsString(%#02x,%#02x) = %q, want %q", tc.or, tc.and, got, tc.want)
		}
	}
}

// TestNullScanFlagsAreDistinguishedFromNoData guards the exact bug psad had to
// fix ("Bugfix for improperly detecting NULL scans", ChangeLog:1226): a NULL
// scan's all-zero flag byte must not be confused with "no TCP packet seen".
func TestNullScanFlagsAreDistinguishedFromNoData(t *testing.T) {
	var st sourceState
	if st.flagsSeen {
		t.Fatal("fresh state claims to have seen flags")
	}
	if m := describeMethod(&st); m != MethodUnknown {
		t.Fatalf("empty state describes as %v, want MethodUnknown", m)
	}
	st.tcpProbes = 1
	st.observeFlags(0)
	if !st.flagsSeen {
		t.Fatal("observeFlags(0) did not record that flags were seen")
	}
	if m := describeMethod(&st); m != MethodNULL {
		t.Fatalf("after a NULL packet, method = %v, want MethodNULL", m)
	}
}

func TestFlagsDetail(t *testing.T) {
	if got := FlagsDetail(0); got != "NULL" {
		t.Errorf("FlagsDetail(0) = %q, want NULL", got)
	}
	if got := FlagsDetail(TCPFin | TCPPsh | TCPUrg); got != "FIN|PSH|URG" {
		t.Errorf("FlagsDetail(xmas) = %q, want FIN|PSH|URG", got)
	}
}

// ---------------------------------------------------------------------------
// the false positives every reference project had to fix
// ---------------------------------------------------------------------------

// TestSynRetransmissionsDoNotCount is the deduplication guarantee. Linux
// retransmits an unanswered SYN up to six times; without deduplication a
// single failed connection attempt looks like six scanned ports. scanlogd
// deduplicates at scanlogd.c:240-245; PortSentry and flowhawk do not, and
// miscount.
func TestSynRetransmissionsDoNotCount(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	// Linux backs off 1s, 2s, 4s, ... between SYN retransmissions, so a single
	// failed connection attempt spans about two minutes. The spacing is kept
	// realistic here; the invariant asserted is therefore the port count, not
	// the score, which legitimately decays over that span.
	delay := uint64(0)
	for i := 0; i < 200; i++ {
		delay += uint64(1+i) * 100 * ms
		if ev := e.Process(synProbe(sec+delay, attacker, victim, 22)); ev != nil {
			t.Fatalf("200 retransmissions to a single port reported as a scan after %d packets", i+1)
		}
	}
	st, ok := e.table.lookup(attacker)
	if !ok {
		t.Fatal("source not tracked")
	}
	if st.distinctPorts != 1 {
		t.Errorf("distinctPorts after 200 retransmissions to one port = %d, want 1", st.distinctPorts)
	}
	if got := e.Score(attacker); got > ProbeWeight(PortSystem, multSynClosed) {
		t.Errorf("score after 200 retransmissions = %d, want at most one probe's worth (%d)",
			got, ProbeWeight(PortSystem, multSynClosed))
	}
}

// TestKnownConnectionReturnTrafficIgnored exercises the advantage a host
// firewall has over a network sensor. scanlogd and PortSentry discard every
// ACK and RST because they cannot tell return traffic apart; we can ask.
func TestKnownConnectionReturnTrafficIgnored(t *testing.T) {
	h := newFakeHost()
	e := newTestEngine(t, testConfig(), h)
	// Simulate a passive-mode FTP transfer: many high ports in quick
	// succession, all of them connections we opened. This is the exact false
	// positive scanlogd's README documents and its port weighting exists to
	// suppress.
	for i := 0; i < 100; i++ {
		p := &Probe{
			TimeNs: sec + uint64(i)*ms, Src: attacker, Dst: victim,
			Proto: ProtoTCP, TCPFlags: TCPSyn | TCPAck, TCPFlagsValid: true,
			SrcPort: 20, DstPort: uint16(50000 + i),
		}
		h.connections[connKey(p)] = true
		if ev := e.Process(p); ev != nil {
			t.Fatalf("passive FTP return traffic reported as a scan at packet %d", i)
		}
	}
	if got := e.Score(attacker); got != 0 {
		t.Errorf("score after known-connection traffic = %d, want 0", got)
	}
}

// TestResetPacketsIgnored: an RST is a rejection, not a probe. Counting it
// would let anyone raise our score by bouncing traffic off us.
func TestResetPacketsIgnored(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	for i := 0; i < 200; i++ {
		flags := TCPRst
		if i%2 == 1 {
			flags = TCPRst | TCPAck
		}
		if ev := e.Process(flagProbe(sec+uint64(i)*ms, attacker, victim, uint16(1000+i), flags)); ev != nil {
			t.Fatalf("RST flood reported as a scan at packet %d", i)
		}
	}
	if got := e.Score(attacker); got != 0 {
		t.Errorf("score after RST flood = %d, want 0", got)
	}
}

// TestNonLocalDestinationIgnored: only packets aimed at one of our own unicast
// addresses count. Portmaster's first attempt used a broadcast heuristic whose
// own comment admitted it "can be abused by an attacker if the SNM is < /24".
func TestNonLocalDestinationIgnored(t *testing.T) {
	h := newFakeHost()
	h.allLocal = false
	h.localUnicast[victim] = true
	e := newTestEngine(t, testConfig(), h)

	broadcast := netip.MustParseAddr("192.0.2.255")
	multicast := netip.MustParseAddr("224.0.0.1")
	other := netip.MustParseAddr("198.51.100.9")
	for _, dst := range []netip.Addr{broadcast, multicast, other} {
		for i := 0; i < 60; i++ {
			if ev := e.Process(synProbe(sec+uint64(i)*ms, attacker, dst, uint16(100+i))); ev != nil {
				t.Fatalf("traffic to non-local destination %s reported as a scan", dst)
			}
		}
	}
	if got := e.Score(attacker); got != 0 {
		t.Errorf("score from non-local destinations = %d, want 0", got)
	}
}

// TestExcludedDiscoveryPortsIgnored covers the protocols that legitimately
// touch several ports: DHCP (Portmaster detect.go), NetBIOS over TCP/IP
// (Portmaster isNetBIOSoverTCPIP) and mDNS/SSDP/LLMNR (PortSentry excludes
// 53, 67 and 137-138 "since they are commonly used and might generate false
// positives", examples/portsentry.conf:40).
func TestExcludedDiscoveryPortsIgnored(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	excluded := DefaultConfig().ExcludedPorts
	for round := 0; round < 20; round++ {
		for i, port := range excluded {
			tn := sec + uint64(round*len(excluded)+i)*ms
			if ev := e.Process(udpProbe(tn, attacker, victim, port)); ev != nil {
				t.Fatalf("discovery traffic to port %d reported as a scan", port)
			}
			if ev := e.Process(synProbe(tn+1, attacker, victim, port)); ev != nil {
				t.Fatalf("discovery traffic to TCP port %d reported as a scan", port)
			}
		}
	}
	if got := e.Score(attacker); got != 0 {
		t.Errorf("score from excluded ports = %d, want 0", got)
	}
}

// TestExemptSourceIgnored: an address on the exemption list is never counted.
// psad had to add auto_block_ignore_ip() after the fact (ChangeLog:1111); the
// list must be exercised, not assumed ("auto-ignore IP addresses and networks
// being missed", ChangeLog:1059).
func TestExemptSourceIgnored(t *testing.T) {
	h := newFakeHost()
	h.exempt[attacker] = true
	e := newTestEngine(t, testConfig(), h)
	ports := make([]uint16, 100)
	for i := range ports {
		ports[i] = uint16(1 + i)
	}
	if ev := feedPorts(e, sec, ms, attacker, victim, ports, synProbe); ev != nil {
		t.Fatal("exempt source was reported as scanning")
	}
	if got := e.Score(attacker); got != 0 {
		t.Errorf("exempt source accumulated a score of %d, want 0", got)
	}
}

// TestStartupGraceSuppressesDetection covers the trap only a project that
// actually ran discovered: at start-up, replies to connections opened before
// the daemon began tracking have no known owner and look exactly like probes
// to closed ports. Portmaster's doc.go: "delay start by 1 Minutes (in order to
// let answer-packets from old sockets arrive (at reboot))".
func TestStartupGraceSuppressesDetection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.StartupGrace = 60 * time.Second
	e := newTestEngine(t, cfg, newFakeHost())

	ports := make([]uint16, 100)
	for i := range ports {
		ports[i] = uint16(1 + i)
	}

	// Inside the grace window, traffic that COULD be a reply does not count.
	// Everything carrying ACK is in that category: a bare ACK, a FIN|ACK, the
	// SYN|ACK of a connection opened before the daemon started.
	ack := func(t uint64, src, dst netip.Addr, port uint16) *Probe {
		return flagProbe(t, src, dst, port, TCPAck)
	}
	if ev := feedPorts(e, 0, 100*ms, attacker, victim, ports, ack); ev != nil {
		t.Fatal("return traffic was reported during the startup grace period")
	}
	if got := e.Score(attacker); got != 0 {
		t.Errorf("score accumulated from return traffic during grace = %d, want 0", got)
	}

	// A SYN is NOT suppressed, because it cannot be a reply to anything this
	// host opened: a peer that believes it has a connection always
	// acknowledges. Applying the grace to everything would make the first
	// sixty seconds of every boot a blind window an attacker need only wait
	// for -- measured that way, a full sweep of ports 1-1023 finishing ten
	// seconds after start-up scored zero and reported nothing.
	e2 := newTestEngine(t, cfg, newFakeHost())
	if ev := feedPorts(e2, 0, 100*ms, attacker, victim, ports, synProbe); ev == nil {
		t.Fatal("a SYN scan during the grace window was not reported: the grace is a" +
			" blind spot rather than a filter on replies")
	}

	// Nor UDP, an ICMP sweep or a protocol scan: none of them can be part of a
	// connection opened before the daemon started. Measured with the grace
	// applied to them, each went unreported for the first minute of every boot.
	e4 := newTestEngine(t, cfg, newFakeHost())
	if ev := feedPorts(e4, 0, 100*ms, attacker, victim, ports, udpProbe); ev == nil {
		t.Fatal("a UDP scan during the grace window was not reported")
	}
	e5 := newTestEngine(t, cfg, newFakeHost())
	if ev := feedICMPTypes(e5, attacker, victim, []uint8{8, 13, 17}); ev == nil {
		t.Fatal("an ICMP sweep during the grace window was not reported")
	}
	e6 := newTestEngine(t, cfg, newFakeHost())
	var protoEv *ScanEvent
	for i, proto := range []uint8{2, 4, 41, 47, 50, 51} {
		if ev := e6.Process(&Probe{TimeNs: uint64(i) * ms, Src: attacker, Dst: victim, Proto: proto}); ev != nil {
			protoEv = ev
		}
	}
	if protoEv == nil {
		t.Fatal("a protocol scan during the grace window was not reported")
	}

	// And after the window, everything counts again.
	e3 := newTestEngine(t, cfg, newFakeHost())
	if ev := feedPorts(e3, 61*sec, ms, attacker, victim, ports, ack); ev == nil {
		t.Fatal("scan not reported after the startup grace period ended")
	}
}

// TestNonInitialFragmentNotScored: a non-initial fragment carries no L4 header
// at any assumed offset, so its port fields are meaningless. scanlogd rejects
// these outright (scanlogd.c:208).
func TestNonInitialFragmentNotScored(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	for i := 0; i < 100; i++ {
		p := synProbe(sec+uint64(i)*ms, attacker, victim, uint16(1+i))
		p.Anomalies |= AnomalyFragment
		if ev := e.Process(p); ev != nil {
			t.Fatalf("fragmented traffic scored as a scan at packet %d", i)
		}
	}
	if got := e.Score(attacker); got != 0 {
		t.Errorf("score from fragments = %d, want 0", got)
	}
}

// TestSynToListeningPortWeighsLess is the Portmaster insight: a SYN to a
// running service is what ordinary clients do, a SYN to a closed port is
// probing.
func TestSynToListeningPortWeighsLess(t *testing.T) {
	open := newFakeHost()
	closed := newFakeHost()
	// Few enough ports that neither run reaches the score ceiling, or both
	// would saturate at the same value and the comparison would be vacuous.
	const nPorts = 10
	for p := uint16(1); p <= nPorts; p++ {
		open.listening[portKey(ProtoTCP, p)] = true
	}
	ports := make([]uint16, nPorts)
	for i := range ports {
		ports[i] = uint16(1 + i)
	}

	eOpen := newTestEngine(t, testConfig(), open)
	eClosed := newTestEngine(t, testConfig(), closed)
	feedPorts(eOpen, sec, ms, attacker, victim, ports, synProbe)
	feedPorts(eClosed, sec, ms, attacker, victim, ports, synProbe)

	so, sc := eOpen.Score(attacker), eClosed.Score(attacker)
	ceiling := testConfig().ScoreThreshold * 2
	if sc >= ceiling {
		t.Fatalf("closed-port run saturated at the ceiling (%d); the comparison would be vacuous", sc)
	}
	if so >= sc {
		t.Errorf("score for open ports (%d) should be lower than for closed ports (%d)", so, sc)
	}
}

// ---------------------------------------------------------------------------
// scoring, decay, thresholds
// ---------------------------------------------------------------------------

func TestDecayReducesScoreOverTime(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(t, cfg, newFakeHost())

	// Two probes on registered ports: 2 * (2*3) = 12 points.
	e.Process(synProbe(sec, attacker, victim, 8080))
	e.Process(synProbe(sec+ms, attacker, victim, 8081))
	start := e.Score(attacker)
	if start == 0 {
		t.Fatal("no score accumulated")
	}
	// Advance by 5 decay intervals; feeding a probe on an already-seen port
	// triggers decay without adding score.
	later := sec + ms + 5*uint64(cfg.DecayInterval)
	e.Process(synProbe(later, attacker, victim, 8080))
	if got := e.Score(attacker); got != start-5 {
		t.Errorf("score after 5 decay intervals = %d, want %d", got, start-5)
	}
}

// TestDecayDoesNotUnderflow guards the bug Portmaster left open for the whole
// life of its patch ("TODO: Integer over-&Underflow on score").
func TestDecayDoesNotUnderflow(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(t, cfg, newFakeHost())
	e.Process(synProbe(sec, attacker, victim, 8080))
	// Jump forward by a century.
	far := sec + uint64(100*365*24*time.Hour)
	e.Process(synProbe(far, attacker, victim, 8080))
	if got := e.Score(attacker); got != 0 {
		t.Errorf("score after a century = %d, want 0", got)
	}
}

// TestClockGoingBackwardsIsSafe: the engine must tolerate a non-monotonic
// timestamp without corrupting its arithmetic. scanlogd guards the same way
// (`now - ts <= threshold && now >= ts`, scanlogd.c:237-238).
func TestClockGoingBackwardsIsSafe(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	e.Process(synProbe(10*sec, attacker, victim, 8080))
	before := e.Score(attacker)
	e.Process(synProbe(1*sec, attacker, victim, 8080)) // earlier than the last
	if got := e.Score(attacker); got != before {
		t.Errorf("score changed on a backwards timestamp: %d -> %d", before, got)
	}
}

// TestScoreCeiling: a long scan must not bank an unbounded score that would
// keep the source hot long after it stopped.
func TestScoreCeiling(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(t, cfg, newFakeHost())
	for i := 0; i < 1000; i++ {
		e.Process(synProbe(sec+uint64(i)*ms, attacker, victim, uint16(1+i)))
	}
	if got := e.Score(attacker); got > cfg.ScoreThreshold*2 {
		t.Errorf("score = %d, exceeds the ceiling of %d", got, cfg.ScoreThreshold*2)
	}
}

// TestAnomalousFlagsTriggerFasterThanSyn: FIN/NULL/Xmas probes are less
// ambiguous than SYNs, so fewer of them should be needed.
func TestAnomalousFlagsTriggerFasterThanSyn(t *testing.T) {
	countUntilDetected := func(flags uint8) int {
		e := newTestEngine(t, testConfig(), newFakeHost())
		for i := 0; i < 500; i++ {
			if ev := e.Process(flagProbe(sec+uint64(i)*ms, attacker, victim, uint16(1+i), flags)); ev != nil {
				return i + 1
			}
		}
		return -1
	}
	syn := countUntilDetected(TCPSyn)
	fin := countUntilDetected(TCPFin)
	if syn < 0 || fin < 0 {
		t.Fatalf("scan not detected (syn=%d, fin=%d)", syn, fin)
	}
	if fin >= syn {
		t.Errorf("FIN scan needed %d probes, SYN scan %d: anomalous flags should trigger sooner", fin, syn)
	}
}

// TestProtocolScanDetection covers nmap -sO, which sends no ports at all, only
// varying IP protocol numbers. psad uses a threshold of 5 distinct protocols
// (psad.conf:111).
func TestProtocolScanDetection(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(t, cfg, newFakeHost())
	protos := []uint8{1, 2, 4, 41, 47, 50, 89, 132}
	var ev *ScanEvent
	for i, pr := range protos {
		p := &Probe{TimeNs: sec + uint64(i)*ms, Src: attacker, Dst: victim, Proto: pr}
		if got := e.Process(p); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Fatal("IP protocol scan not detected")
	}
	if !ev.IsProtocolScan {
		t.Error("event does not flag IsProtocolScan")
	}
	if ev.Method != MethodProtocol {
		t.Errorf("Method = %v, want MethodProtocol", ev.Method)
	}
	if ev.Protocols < cfg.ProtoScanMinProtocols {
		t.Errorf("Protocols = %d, want at least %d", ev.Protocols, cfg.ProtoScanMinProtocols)
	}
}

// TestOrdinaryProtocolMixIsNotAProtocolScan: seeing tcp+udp+icmp from one host
// is unremarkable, which is exactly why psad's threshold is 5 and not 3.
func TestOrdinaryProtocolMixIsNotAProtocolScan(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	for i, pr := range []uint8{ProtoTCP, ProtoUDP, ProtoICMP} {
		p := &Probe{TimeNs: sec + uint64(i)*ms, Src: attacker, Dst: victim, Proto: pr, DstPort: 9999}
		e.Process(p)
	}
	if st, ok := e.table.lookup(attacker); ok && st.protoScan {
		t.Error("tcp+udp+icmp was misreported as an IP protocol scan")
	}
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

func TestIPv6ScanDetected(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	ports := make([]uint16, 40)
	for i := range ports {
		ports[i] = uint16(20 + i)
	}
	ev := feedPorts(e, sec, ms, attacker6, victim6, ports, synProbe)
	if ev == nil {
		t.Fatal("IPv6 SYN scan not detected")
	}
	if ev.Src != attacker6 {
		t.Errorf("Src = %v, want %v", ev.Src, attacker6)
	}
	if !ev.Src.Is6() {
		t.Error("event source is not IPv6")
	}
}

// TestIPv4AndIPv6AreTrackedSeparately: the same host reaching us over both
// families must not have its two scores merged, since the two addresses are
// blocked separately.
func TestIPv4AndIPv6AreTrackedSeparately(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	for i := 0; i < 20; i++ {
		e.Process(synProbe(sec+uint64(i)*ms, attacker, victim, uint16(100+i)))
		e.Process(synProbe(sec+uint64(i)*ms, attacker6, victim6, uint16(100+i)))
	}
	s4, s6 := e.Score(attacker), e.Score(attacker6)
	if s4 == 0 || s6 == 0 {
		t.Fatalf("expected both families to accumulate: v4=%d v6=%d", s4, s6)
	}
	if e.table.len() != 2 {
		t.Errorf("tracked sources = %d, want 2 (one per family)", e.table.len())
	}
}

// TestIPv6ExtensionHeaderAnomalyRecorded: Topera hides the TCP header behind
// seven or more empty extension headers so analysers give up quietly
// (psad:1709). Exceeding the bounded walk must surface as evidence, not
// silence.
func TestIPv6ExtensionHeaderAnomalyRecorded(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	var ev *ScanEvent
	for i := 0; i < 40; i++ {
		p := synProbe(sec+uint64(i)*ms, attacker6, victim6, uint16(20+i))
		p.Anomalies |= AnomalyExtHeaderChain
		if got := e.Process(p); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Fatal("scan not detected")
	}
	if ev.Anomalies&AnomalyExtHeaderChain == 0 {
		t.Error("excessive IPv6 extension header chain not reported in the event")
	}
}

// ---------------------------------------------------------------------------
// bounded state
// ---------------------------------------------------------------------------

// TestStateIsBounded is the property four of the five reference projects lack.
// PortSentry allows a million malloc'd entries per family
// (state_machine.c:19), Portmaster's map is unbounded with an unimplemented
// "TODO: regular cleanup", flowhawk's Go maps grow without limit. Only
// scanlogd bounds its state, with a 256-entry static array.
func TestStateIsBounded(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSources = 128
	e := newTestEngine(t, cfg, newFakeHost())

	// 50 000 distinct spoofed sources, as a decoy or spoofed-source scan would
	// produce.
	for i := 0; i < 50000; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		e.Process(synProbe(sec+uint64(i)*ms, src, victim, 22))
	}
	if got := e.table.len(); got > cfg.MaxSources {
		t.Fatalf("tracked sources = %d, exceeds MaxSources = %d", got, cfg.MaxSources)
	}
	if e.table.evictedCount() == 0 {
		t.Error("no eviction recorded despite far more sources than capacity")
	}
}

// TestPerSourceStateDoesNotGrow: an individual entry must stay a fixed size
// however many ports are probed. scanlogd keeps a port array capped at
// SCAN_MAX_COUNT-1 and Portmaster appends to an unbounded slice; we use a
// fixed-size ring of recent ports, so the assertion is that the sample list is
// capped.
func TestPerSourceStateDoesNotGrow(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	for i := 0; i < 65000; i++ {
		e.Process(synProbe(sec+uint64(i)*ms, attacker, victim, uint16(i%65536)))
	}
	st, ok := e.table.lookup(attacker)
	if !ok {
		t.Fatal("source not tracked")
	}
	if int(st.nSample) > sampledPorts {
		t.Errorf("sample list holds %d ports, cap is %d", st.nSample, sampledPorts)
	}
	if int(st.nDstSeen) > len(st.dstSeen) {
		t.Errorf("destination list holds %d entries, cap is %d", st.nDstSeen, len(st.dstSeen))
	}
}

func TestIdleSourcesExpire(t *testing.T) {
	cfg := testConfig()
	cfg.IdleExpiry = time.Minute
	e := newTestEngine(t, cfg, newFakeHost())
	for i := 0; i < 10; i++ {
		src := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})
		e.Process(synProbe(sec, src, victim, 22))
	}
	if e.table.len() != 10 {
		t.Fatalf("tracked sources = %d, want 10", e.table.len())
	}
	if removed := e.Expire(sec + uint64(2*time.Minute)); removed != 10 {
		t.Errorf("Expire removed %d sources, want 10", removed)
	}
	if e.table.len() != 0 {
		t.Errorf("tracked sources after expiry = %d, want 0", e.table.len())
	}
}

// TestExpireStopsAtFirstLiveEntry checks that expiry costs time proportional
// to what it removes, not to the table size.
func TestExpireStopsAtFirstLiveEntry(t *testing.T) {
	cfg := testConfig()
	cfg.IdleExpiry = time.Minute
	e := newTestEngine(t, cfg, newFakeHost())
	// Five sources idle well beyond the expiry, then five seen 30s ago, which
	// is comfortably inside the one-minute expiry.
	now := sec + uint64(10*time.Minute)
	for i := 0; i < 5; i++ {
		e.Process(synProbe(sec, netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), victim, 22))
	}
	for i := 5; i < 10; i++ {
		e.Process(synProbe(now-uint64(30*time.Second), netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), victim, 22))
	}
	removed := e.Expire(now)
	if removed != 5 {
		t.Errorf("Expire removed %d, want 5", removed)
	}
	if e.table.len() != 5 {
		t.Errorf("tracked sources = %d, want 5", e.table.len())
	}
}

func TestForgetDropsState(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	e.Process(synProbe(sec, attacker, victim, 22))
	if e.Score(attacker) == 0 {
		t.Fatal("no score accumulated")
	}
	e.Forget(attacker)
	if got := e.Score(attacker); got != 0 {
		t.Errorf("score after Forget = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// alert rate limiting
// ---------------------------------------------------------------------------

// TestAlertRateLimiting is what stops a decoy scan from producing one desktop
// notification per forged source. scanlogd has capped alerts since 1998
// (safe_log, scanlogd.c:172-186); neither Portmaster's PR nor flowhawk does.
func TestAlertRateLimiting(t *testing.T) {
	cfg := testConfig()
	cfg.AlertsPerMinute = 3
	e := newTestEngine(t, cfg, newFakeHost())

	events := 0
	// 100 distinct sources each performing a full scan, within one minute.
	for s := 0; s < 100; s++ {
		src := netip.AddrFrom4([4]byte{198, 51, 100, byte(s)})
		for i := 0; i < 40; i++ {
			tn := sec + uint64(s)*100*ms + uint64(i)*ms
			if ev := e.Process(synProbe(tn, src, victim, uint16(20+i))); ev != nil {
				events++
			}
		}
	}
	if events > cfg.AlertsPerMinute {
		t.Errorf("emitted %d events in one minute, cap is %d", events, cfg.AlertsPerMinute)
	}
	if events == 0 {
		t.Error("no event emitted at all")
	}
	if st := e.Stats(); st.EventsSuppressed == 0 {
		t.Error("suppressed events were not counted")
	}
}

// TestSuppressedCountIsReported: after suppression, the next emitted event must
// say how many were withheld, so the user is not told a single host is
// scanning when a hundred are.
func TestSuppressedCountIsReported(t *testing.T) {
	cfg := testConfig()
	cfg.AlertsPerMinute = 1
	e := newTestEngine(t, cfg, newFakeHost())

	scan := func(tBase uint64, src netip.Addr) *ScanEvent {
		var ev *ScanEvent
		for i := 0; i < 40; i++ {
			if got := e.Process(synProbe(tBase+uint64(i)*ms, src, victim, uint16(20+i))); got != nil && ev == nil {
				ev = got
			}
		}
		return ev
	}
	if ev := scan(sec, netip.MustParseAddr("198.51.100.1")); ev == nil {
		t.Fatal("first scan not reported")
	}
	// Same minute: suppressed.
	if ev := scan(2*sec, netip.MustParseAddr("198.51.100.2")); ev != nil {
		t.Fatal("second scan should have been suppressed")
	}
	// Next minute: reported, and must carry the suppressed count.
	ev := scan(90*sec, netip.MustParseAddr("198.51.100.3"))
	if ev == nil {
		t.Fatal("third scan not reported after the rate-limit window rolled over")
	}
	if ev.SuppressedSince == 0 {
		t.Error("SuppressedSince = 0, want the number of withheld events")
	}
}

// TestSuppressedCountCountsSourcesNotPackets: the figure the user reads as the
// scale of the attack must not be one the attacker writes.
//
// If a refused source left st.reported false, every subsequent packet would go
// back through allowEvent and increment the counter. Measured that way, with
// AlertsPerMinute = 1: source A takes the slot, source B crosses the threshold
// and then keeps sending, and the next event to get through announces "2957
// further scan alert(s) were suppressed" when exactly ONE source was ever
// silenced. An operator reading that number reads it as a reason to raise
// AlertsPerMinute -- to disarm the one protection against a decoy scan's flood
// of notifications. The same retry would take the global limiter mutex on the
// packet path while holding a shard lock.
func TestSuppressedCountCountsSourcesNotPackets(t *testing.T) {
	cfg := testConfig()
	cfg.AlertsPerMinute = 1
	e := newTestEngine(t, cfg, newFakeHost())

	scan := func(tBase uint64, src netip.Addr, n int) {
		for i := 0; i < n; i++ {
			e.Process(synProbe(tBase+uint64(i)*ms, src, victim, uint16(20+i%200)))
		}
	}

	// A takes the only slot in the window.
	scan(sec, netip.MustParseAddr("198.51.100.1"), 40)
	// B crosses the threshold, is refused, and then sends three thousand more
	// packets. Exactly one source has been silenced.
	scan(2*sec, netip.MustParseAddr("198.51.100.2"), 3000)

	if got := e.Stats().EventsSuppressed; got != 1 {
		t.Errorf("EventsSuppressed = %d after one silenced source sent 3000 packets, want 1", got)
	}

	// The next window: C gets a slot and carries the count.
	var ev *ScanEvent
	for i := 0; i < 40; i++ {
		if got := e.Process(synProbe(90*sec+uint64(i)*ms, netip.MustParseAddr("198.51.100.3"), victim, uint16(20+i))); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Fatal("no event after the window rolled over")
	}
	if ev.SuppressedSince != 1 {
		t.Errorf("SuppressedSince = %d, want 1: the text shown to the user says"+
			" %d further scan alerts were suppressed", ev.SuppressedSince, ev.SuppressedSince)
	}
}

// TestSuppressedSourceStopsAskingWithinTheWindow: a source refused a slot must
// not consult the global limiter again until the window can have rolled.
//
// This is the throughput half of the problem above. Without it, with the
// default budget, four sources over the threshold -- 120 packets -- would be
// enough to put a process-wide mutex in the path of every packet from every
// one of them, taken while already holding a shard lock. Measured that way:
// 1.49x slower on four cores, undoing exactly what the sharding is for.
func TestSuppressedSourceStopsAskingWithinTheWindow(t *testing.T) {
	cfg := testConfig()
	cfg.AlertsPerMinute = 1
	e := newTestEngine(t, cfg, newFakeHost())

	for i := 0; i < 40; i++ {
		e.Process(synProbe(sec+uint64(i)*ms, netip.MustParseAddr("198.51.100.1"), victim, uint16(20+i)))
	}

	src := netip.MustParseAddr("198.51.100.2")
	for i := 0; i < 40; i++ {
		e.Process(synProbe(2*sec+uint64(i)*ms, src, victim, uint16(20+i)))
	}

	// EventsSuppressed rises on every refusal, so it counts the calls: within
	// the window the budget cannot grow, and a call can only be refused.
	before := e.Stats().EventsSuppressed
	for i := 0; i < 500; i++ {
		e.Process(synProbe(3*sec+uint64(i)*ms, src, victim, uint16(400+i)))
	}
	if got := e.Stats().EventsSuppressed - before; got != 0 {
		t.Errorf("a refused source consulted the global limiter %d more times in the same"+
			" window, over 500 packets; want 0", got)
	}

	// And it must ask again once the window has rolled, or the source would be
	// silenced for ever. Here the budget is free, so it is granted.
	var ev *ScanEvent
	for i := 0; i < 40; i++ {
		if got := e.Process(synProbe(90*sec+uint64(i)*ms, src, victim, uint16(900+i))); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Error("the source was never reported after the window rolled; it would stay silent for ever")
	}
}

// TestReportCooldown: one source must not produce a new event on every packet
// once it has crossed the threshold.
func TestReportCooldown(t *testing.T) {
	cfg := testConfig()
	cfg.AlertsPerMinute = maxAlertsPerMinute
	cfg.ReportCooldown = 5 * time.Minute
	e := newTestEngine(t, cfg, newFakeHost())

	events := 0
	for i := 0; i < 2000; i++ {
		if ev := e.Process(synProbe(sec+uint64(i)*ms, attacker, victim, uint16(i%60000))); ev != nil {
			events++
		}
	}
	if events != 1 {
		t.Errorf("emitted %d events during a 2s continuous scan, want 1 (cooldown)", events)
	}
}

// ---------------------------------------------------------------------------
// block eligibility
// ---------------------------------------------------------------------------

// TestUDPOnlyScanIsNotBlockEligible: a UDP source address costs nothing to
// forge, which is why PortSentry warns that UDP blocking enables "a possible
// Denial of service attack" (examples/portsentry.conf:110-113).
func TestUDPOnlyScanIsNotBlockEligible(t *testing.T) {
	cfg := testConfig()
	cfg.Block.Policy = BlockAuto
	cfg.Block.RequireTCPEvidence = true
	e := newTestEngine(t, cfg, newFakeHost())

	ports := make([]uint16, 200)
	for i := range ports {
		ports[i] = uint16(1 + i)
	}
	ev := feedPorts(e, sec, ms, attacker, victim, ports, udpProbe)
	if ev == nil {
		t.Fatal("UDP scan not detected")
	}
	if ev.HasTCPEvidence {
		t.Error("HasTCPEvidence set for a UDP-only scan")
	}
	if ev.BlockEligible {
		t.Error("UDP-only scan reported as block-eligible despite RequireTCPEvidence")
	}
}

func TestTCPScanIsBlockEligible(t *testing.T) {
	cfg := testConfig()
	cfg.Block.Policy = BlockAuto
	e := newTestEngine(t, cfg, newFakeHost())
	ports := make([]uint16, 40)
	for i := range ports {
		ports[i] = uint16(20 + i)
	}
	ev := feedPorts(e, sec, ms, attacker, victim, ports, synProbe)
	if ev == nil {
		t.Fatal("TCP scan not detected")
	}
	if !ev.HasTCPEvidence {
		t.Error("HasTCPEvidence not set for a TCP scan")
	}
	if !ev.BlockEligible {
		t.Error("TCP scan not reported as block-eligible under BlockAuto")
	}
}

func TestBlockNeverPolicyDisablesEligibility(t *testing.T) {
	cfg := testConfig()
	cfg.Block.Policy = BlockNever
	e := newTestEngine(t, cfg, newFakeHost())
	ports := make([]uint16, 40)
	for i := range ports {
		ports[i] = uint16(20 + i)
	}
	ev := feedPorts(e, sec, ms, attacker, victim, ports, synProbe)
	if ev == nil {
		t.Fatal("scan not detected")
	}
	if ev.BlockEligible {
		t.Error("BlockEligible set despite Block.Policy = never")
	}
}

// ---------------------------------------------------------------------------
// event contents
// ---------------------------------------------------------------------------

func TestEventCarriesEvidence(t *testing.T) {
	h := newFakeHost()
	h.onLink[attacker] = true
	e := newTestEngine(t, testConfig(), h)
	e.SetWallClockAnchor(time.Unix(1700000000, 0).UTC(), 0)

	mac := [6]byte{0x02, 0x00, 0x5e, 0x11, 0x22, 0x33}
	var ev *ScanEvent
	for i := 0; i < 40; i++ {
		p := synProbe(sec+uint64(i)*ms, attacker, victim, uint16(20+i))
		p.SrcMAC, p.HasMAC = mac, true
		p.IfaceIndex = 7
		if got := e.Process(p); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Fatal("scan not detected")
	}
	if ev.Src != attacker {
		t.Errorf("Src = %v, want %v", ev.Src, attacker)
	}
	if !ev.HasMAC || ev.SrcMAC != mac {
		t.Errorf("SrcMAC = %v (has=%v), want %v", ev.SrcMAC, ev.HasMAC, mac)
	}
	if !ev.MACIsSourceOwn {
		t.Error("MACIsSourceOwn not set for an on-link source")
	}
	if ev.DistinctPorts < 2 {
		t.Errorf("DistinctPorts = %d, want the number of probed ports", ev.DistinctPorts)
	}
	if ev.MinPort != 20 {
		t.Errorf("MinPort = %d, want 20", ev.MinPort)
	}
	if len(ev.SamplePorts) == 0 {
		t.Error("SamplePorts is empty")
	}
	if ev.IfaceIndex != 7 {
		t.Errorf("IfaceIndex = %d, want 7", ev.IfaceIndex)
	}
	if ev.FirstSeen.IsZero() || ev.LastSeen.IsZero() {
		t.Error("wall-clock timestamps not populated despite SetWallClockAnchor")
	}
	if ev.LastSeen.Before(ev.FirstSeen) {
		t.Error("LastSeen precedes FirstSeen")
	}
	if len(ev.Targets) == 0 || ev.Targets[0] != victim {
		t.Errorf("Targets = %v, want to include %v", ev.Targets, victim)
	}
}

// TestMACNotClaimedForOffLinkSource: the MAC in the frame is the previous
// hop's. Presenting a router's MAC as the attacker's would be a fabrication.
func TestMACNotClaimedForOffLinkSource(t *testing.T) {
	h := newFakeHost() // attacker is not on-link
	e := newTestEngine(t, testConfig(), h)
	var ev *ScanEvent
	for i := 0; i < 40; i++ {
		p := synProbe(sec+uint64(i)*ms, attacker, victim, uint16(20+i))
		p.SrcMAC, p.HasMAC = [6]byte{0xaa, 0, 0, 0, 0, 1}, true
		if got := e.Process(p); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Fatal("scan not detected")
	}
	if !ev.HasMAC {
		t.Error("HasMAC should still report that a link address was observed")
	}
	if ev.MACIsSourceOwn {
		t.Error("MACIsSourceOwn set for an off-link source: that MAC belongs to a router")
	}
}

// ---------------------------------------------------------------------------
// deduplication filter quality
// ---------------------------------------------------------------------------

// TestPortFilterNeverMissesARepeat: within a generation the filter must have no
// false negatives, or deduplication breaks and the six SYN retransmissions of
// one unanswered connection count as six scanned ports.
func TestPortFilterNeverMissesARepeat(t *testing.T) {
	var st sourceState

	// Deduplication is exact: every new port is accepted exactly once, which a
	// Bloom filter could not promise, since a false positive would drop one.
	// One short of a generation, so the lazy clear does not run.
	var accepted []uint16
	for p := 0; p < portFilterGeneration-1; p++ {
		if st.addPort(ProtoTCP, uint16(p)) {
			accepted = append(accepted, uint16(p))
		}
	}
	if st.generations != 0 {
		t.Fatalf("the filter rolled over early: %d generations", st.generations)
	}
	if len(accepted) != portFilterGeneration-1 {
		t.Fatalf("%d of %d distinct ports accepted: a false positive dropped a new port",
			len(accepted), portFilterGeneration-1)
	}

	// Re-inserting rejects, so portsThisGen does not move and the generation
	// stays the same throughout.
	for _, p := range accepted {
		if st.addPort(ProtoTCP, p) {
			t.Fatalf("port %d reported as new on a second insertion in the same generation", p)
		}
	}
	if st.generations != 0 {
		t.Fatalf("re-insertions rolled the generation over")
	}
}

// TestPortFilterCannotSaturate pins that no sequence of ports makes a source
// immune to scoring.
//
// Scoring happens only when addPort accepts a port. An unbounded 512-bit filter
// sets every bit after roughly 350 accepted ports and then answers "already
// seen" to everything, for ever: an off switch for detection that any sender
// can throw deliberately with a few hundred cheap probes, and that nothing ever
// undoes while they keep sending.
func TestPortFilterCannotSaturate(t *testing.T) {
	var st sourceState

	// Far past the point where an unbounded filter would be full.
	for round := 0; round < 4; round++ {
		for p := 0; p <= 0xffff; p++ {
			st.addPort(ProtoTCP, uint16(p))
		}
	}
	if st.generations == 0 {
		t.Fatalf("the filter never rolled over")
	}

	// Whatever came before, a fresh port must still be able to count. Try a
	// handful so a single false positive does not fail the test.
	accepted := 0
	for i := 0; i < 32; i++ {
		if st.addPort(ProtoUDP, uint16(40000+i)) {
			accepted++
		}
	}
	if accepted == 0 {
		t.Fatalf("no port was accepted after %d generations: the filter is saturated and detection is off",
			st.generations)
	}
	t.Logf("%d/32 accepted after %d generations (%d distinct ports counted)",
		accepted, st.generations, st.distinctPorts)
}

// TestSaturationBypassIsClosed drives the whole engine the way such an
// exploit would: seed the filter under the threshold, then scan freely.
func TestSaturationBypassIsClosed(t *testing.T) {
	h := newFakeHost()
	cfg := testConfig()
	e := newTestEngine(t, cfg, h)

	// Seeding phase: cheap UDP probes on dynamic ports, paced so the score
	// never crosses. Enough of them to fill an unbounded filter several times.
	tNs := uint64(0)
	for i := 0; i < 3000; i++ {
		tNs += uint64(cfg.DecayInterval)
		if ev := e.Process(udpProbe(tNs, attacker, victim, uint16(50000+i%15000))); ev != nil {
			t.Logf("seeding was itself reported at probe %d, which is fine", i)
			break
		}
	}

	// Now the real scan: SYN to closed system ports, fast.
	var ev *ScanEvent
	for i := 0; i < 200 && ev == nil; i++ {
		tNs += ms
		ev = e.Process(synProbe(tNs, attacker, victim, uint16(1+i)))
	}
	if ev == nil {
		t.Fatalf("after seeding, a %d-port SYN scan produced no event: the filter is an off switch",
			200)
	}
}

// TestSameProtoDifferentPortsAreDistinct checks that TCP/53 and UDP/53 are
// counted separately, the distinction Portmaster added in its final revision.
func TestSameProtoDifferentPortsAreDistinct(t *testing.T) {
	var st sourceState
	if !st.addPort(ProtoTCP, 53) {
		t.Fatal("first TCP/53 not new")
	}
	if !st.addPort(ProtoUDP, 53) {
		t.Error("UDP/53 treated as already seen after TCP/53")
	}
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

// TestConcurrentProcess exercises the engine from several goroutines, so that
// `go test -race` can prove the locking is sound. The eBPF ring buffer is read
// by one goroutine today, but the AF_PACKET source uses one per interface.
func TestConcurrentProcess(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			src := netip.AddrFrom4([4]byte{203, 0, 113, byte(g)})
			for i := 0; i < 500; i++ {
				e.Process(synProbe(sec+uint64(i)*ms, src, victim, uint16(i%1000)))
			}
			e.Expire(sec)
			e.Stats()
			e.Score(src)
		}(g)
	}
	wg.Wait()
	if st := e.Stats(); st.ProbesSeen != 8*500 {
		t.Errorf("ProbesSeen = %d, want %d", st.ProbesSeen, 8*500)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestUnreadableFlagsAreNotReportedAsNullScan is the honesty guarantee for
// fragmented scans. nmap -f puts the flag octet in a later fragment, so the
// flags field is simply absent -- which is not the same thing as a NULL scan,
// where the sender deliberately set no bits. Confusing the two would report a
// technique that was never observed.
func TestUnreadableFlagsAreNotReportedAsNullScan(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	var ev *ScanEvent
	for i := 0; i < 40; i++ {
		p := synProbe(sec+uint64(i)*ms, attacker, victim, uint16(20+i))
		p.TCPFlags = 0
		p.TCPFlagsValid = false // the flags were never in the captured bytes
		p.Anomalies |= AnomalyTruncated
		if got := e.Process(p); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Fatal("fragmented scan not detected; its destination ports are readable and must be counted")
	}
	if ev.Method == MethodNULL {
		t.Fatal("unread flags reported as a NULL scan: that technique was never observed")
	}
	if ev.Method != MethodFragmentedTCP {
		t.Errorf("Method = %v, want MethodFragmentedTCP", ev.Method)
	}
	if !contains(ev.MethodDetail, "undetermined") {
		t.Errorf("MethodDetail = %q, must state that the technique is undetermined", ev.MethodDetail)
	}
}

// TestLRUFloodCannotEraseAScanner pins that a flood of forged sources cannot
// evict a scanner's accumulated state for free.
//
// Strict least-recently-used eviction is a detection bypass, not just a
// capacity policy: an attacker who interleaves MaxSources packets from forged
// addresses between two of their own probes pushes their own entry off the back
// of the list, and it comes back blank. Their scan then restarts from zero at
// every probe and never reaches the threshold. Measured against an engine
// with strict LRU eviction, that cost about 4096 packets per probe -- two
// seconds of a gigabit link for complete invisibility.
func TestLRUFloodCannotEraseAScanner(t *testing.T) {
	h := newFakeHost()
	cfg := testConfig()
	cfg.MaxSources = 64
	e := newTestEngine(t, cfg, h)

	tNs := uint64(0)
	probe := func(src netip.Addr, port uint16) *ScanEvent {
		tNs += ms
		return e.Process(synProbe(tNs, src, victim, port))
	}

	// The scanner establishes real evidence: several distinct ports.
	for i := 0; i < 4; i++ {
		probe(attacker, uint16(20+i))
	}

	// Now the flood, interleaved with the scan. Each round pushes more than a
	// full table of single-packet forged sources.
	var ev *ScanEvent
	for round := 0; round < 40 && ev == nil; round++ {
		for f := 0; f < cfg.MaxSources+8; f++ {
			probe(netip.AddrFrom4([4]byte{198, 51, byte(round), byte(f)}), 80)
		}
		ev = probe(attacker, uint16(1000+round))
	}

	if ev == nil {
		t.Fatalf("the scanner was never reported: a flood of forged sources erased its state")
	}
	if ev.Src != attacker {
		t.Fatalf("reported %s, want the scanner %s", ev.Src, attacker)
	}
	t.Logf("scanner still reported after the flood: %d distinct ports, score %d, %d evictions",
		ev.DistinctPorts, ev.Score, e.Stats().SourcesEvicted)
}

// TestReportedPortCountIsNotInflatedByGenerationRotation: the number the user
// reads as the scale of the scan must not exceed what is arithmetically
// possible.
//
// The port filter is cleared every portFilterGeneration accepted ports, so it
// can never saturate into an off switch. A port seen again in a later generation
// is then accepted again and counted again: measured, 200 genuinely distinct
// ports, repeated, reported 396. Unbounded, it passes 65535 and stops meaning
// anything.
func TestReportedPortCountIsNotInflatedByGenerationRotation(t *testing.T) {
	h := newFakeHost()
	e := newTestEngine(t, testConfig(), h)

	const nPorts = 200
	const firstPort = 1000
	var last *ScanEvent
	tNs := uint64(0)
	// Several passes over the same 200 ports, enough to rotate the filter more
	// than once.
	for pass := 0; pass < 4; pass++ {
		for i := 0; i < nPorts; i++ {
			tNs += ms
			if ev := e.Process(synProbe(tNs, attacker, victim, uint16(firstPort+i))); ev != nil {
				last = ev
			}
		}
	}
	if last == nil {
		t.Fatal("the scan was never reported")
	}

	st, ok := e.table.lookup(attacker)
	if !ok {
		t.Fatal("the source is not in the table")
	}
	if st.generations == 0 {
		t.Fatal("the filter never rotated; this test is not exercising the case it exists for")
	}
	reported := reportedPortCount(&st)
	t.Logf("accepted %d ports over %d generations for %d genuinely distinct ones; reported %d",
		st.distinctPorts, st.generations, nPorts, reported)

	if st.distinctPorts <= nPorts {
		t.Fatalf("the raw counter is %d for %d distinct ports; this test is meant to run"+
			" against an inflated one", st.distinctPorts, nPorts)
	}
	if reported > nPorts {
		t.Errorf("reported %d ports for %d genuinely distinct ones: the figure a user reads"+
			" as the scale of the attack is inflated", reported, nPorts)
	}
	if reported == 0 {
		t.Error("reported 0 ports for a 200-port scan")
	}
	if st.minPort != firstPort || st.maxPort != firstPort+nPorts-1 {
		t.Errorf("range = %d..%d, want %d..%d", st.minPort, st.maxPort, firstPort, firstPort+nPorts-1)
	}
	// An emitted event carries the clamped figure, not the raw counter.
	if last.DistinctPorts > uint32(last.MaxPort)-uint32(last.MinPort)+1 {
		t.Errorf("the event reports %d ports over the range %d..%d, which is impossible",
			last.DistinctPorts, last.MinPort, last.MaxPort)
	}
}

// TestFloodDoesNotEraseAScannerThatHasEvidence: once a source has accumulated
// evidence, forged addresses carrying less than it do not displace it.
//
// The claim is deliberately narrow. A predicate -- keep a source with two
// ports and a quarter of the threshold -- would be defeated by three SYNs per
// forged address. Ranking by score withstands that, which is what is checked
// here: at 1, 2 and 3 packets per forged address, a scanner that has already
// scored survives.
//
// What it does NOT establish is that the flood costs as much as the scan. See
// TestFloodFromTheFirstProbeStillHidesAScan: an attacker who floods from the
// start never lets the scanner accumulate anything, so there is no head start
// like the one this test grants, and the bypass stays open at a fixed price.
func TestFloodDoesNotEraseAScannerThatHasEvidence(t *testing.T) {
	for _, perSource := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("%d-packets-per-forged-source", perSource), func(t *testing.T) {
			h := newFakeHost()
			cfg := testConfig()
			cfg.MaxSources = 64
			e := newTestEngine(t, cfg, h)

			tNs := uint64(0)
			probe := func(src netip.Addr, port uint16) *ScanEvent {
				tNs += ms
				return e.Process(synProbe(tNs, src, victim, port))
			}

			for i := 0; i < 4; i++ {
				probe(attacker, uint16(20+i))
			}

			var ev *ScanEvent
			for round := 0; round < 40 && ev == nil; round++ {
				for f := 0; f < cfg.MaxSources+8; f++ {
					src := netip.AddrFrom4([4]byte{198, 51, byte(round), byte(f)})
					// Distinct low ports, which is what makes each forged source
					// look like evidence to a predicate.
					for k := 0; k < perSource; k++ {
						probe(src, uint16(21+k))
					}
				}
				ev = probe(attacker, uint16(1000+round))
			}

			if ev == nil {
				t.Fatalf("%d packets per forged source erased a scanner that had already"+
					" scored", perSource)
			}
			if ev.Src != attacker {
				t.Fatalf("reported %s, want the scanner %s", ev.Src, attacker)
			}
			t.Logf("scanner reported: score %d over %d ports, %d evictions",
				ev.Score, ev.DistinctPorts, e.Stats().SourcesEvicted)
		})
	}
}

// TestFloodFromTheFirstProbeStillHidesAScan states the limit of the eviction
// hardening, as a test, so that nobody has to rediscover it from the comments.
//
// A bounded table cannot survive an attacker who presents more distinct source
// addresses than it holds. Ranking eviction by score closes the cheap variants
// -- a forged address with one, two or three packets does not displace a
// scanner that has accumulated evidence -- but the scanner and the flood are the
// same person. By flooding from the FIRST probe, the attacker never lets their
// own entry accumulate anything, so the forged addresses only ever have to match
// the value of a single probe.
//
// This test asserts the UNCOMFORTABLE fact rather than hiding it: the scan is
// not detected. It exists so that a future change which claims to close the
// bypass has to come here and say so, and so that the eviction-pressure alert
// below is understood as the actual mitigation.
func TestFloodFromTheFirstProbeStillHidesAScan(t *testing.T) {
	h := newFakeHost()
	cfg := testConfig()
	cfg.MaxSources = 64
	e := newTestEngine(t, cfg, h)

	tNs := uint64(0)
	probe := func(src netip.Addr, port uint16) *ScanEvent {
		tNs += ms
		return e.Process(synProbe(tNs, src, victim, port))
	}

	// No head start: the flood runs from before the first real probe.
	var ev *ScanEvent
	for round := 0; round < 60 && ev == nil; round++ {
		for f := 0; f < cfg.MaxSources+8; f++ {
			probe(netip.AddrFrom4([4]byte{198, 51, byte(round), byte(f)}), 80)
		}
		ev = probe(attacker, uint16(1000+round))
	}

	st, tracked := e.table.lookup(attacker)
	score := uint32(0)
	if tracked {
		score = st.score
	}
	evicted, turnovers := e.EvictionPressure()
	t.Logf("60 probes behind a flood: detected=%v, scanner score=%d, %d evictions (%.0f turnovers)",
		ev != nil, score, evicted, turnovers)

	if ev != nil {
		t.Log("NOTE: the scan was detected. If this is the result of a deliberate" +
			" improvement, replace this test with one that states the new guarantee" +
			" and says what it costs an attacker.")
	}

	// What the daemon CAN do about it: the pressure must be loud enough to
	// trigger the alert, because that alert is the only thing standing between
	// this attack and complete silence.
	if turnovers < evictionPressureTurnovers {
		t.Errorf("the flood produced %.1f table turnovers, under the %d that raise an"+
			" alert: the one bypass a bounded table cannot close would go unreported",
			turnovers, evictionPressureTurnovers)
	}
}

// TestEvictionRanksByTheScoreNow: eviction must compare sources as of now, not
// as of whenever each of them last sent a packet.
//
// The leaky bucket only runs when a packet from that source arrives, so a source
// that stops sending keeps its last score for ever. Eviction candidates are, by
// definition, exactly the entries nothing has arrived for -- so ranking them by
// the stored score compares numbers measured at different times. Nine packets
// then bought permanent residency: a forged source scored to 108 and abandoned
// outranked a scanner that had just started, for as long as the table lived, and
// filling the table with such entries is a one-off cost after which every
// eviction candidate outranks every new arrival.
func TestEvictionRanksByTheScoreNow(t *testing.T) {
	h := newFakeHost()
	cfg := testConfig()
	cfg.MaxSources = 64
	e := newTestEngine(t, cfg, h)

	// One source scores properly, then goes quiet for long enough that its score
	// would have decayed away entirely.
	stale := netip.MustParseAddr("198.51.100.7")
	tNs := uint64(sec)
	for i := 0; i < 12; i++ {
		tNs += ms
		e.Process(synProbe(tNs, stale, victim, uint16(20+i)))
	}
	st, ok := e.table.lookup(stale)
	if !ok {
		t.Fatal("the seeded source is not in the table")
	}
	stored := st.score
	if stored < cfg.ScoreThreshold/2 {
		t.Fatalf("the seeded source only reached %d; this test needs it to score well", stored)
	}

	// Long enough for the leaky bucket to have emptied it several times over.
	quiet := tNs + uint64(cfg.DecayInterval)*uint64(stored)*2

	st, _ = e.table.lookup(stale)
	if got := st.score; got != stored {
		t.Fatalf("the stored score changed on its own: %d -> %d", stored, got)
	}
	shard := e.table.shardFor(stale)
	shard.mu.Lock()
	ranked := shard.evictionRank(&st, quiet)
	shard.mu.Unlock()
	if ranked != 0 {
		t.Errorf("a source that scored %d and then went quiet for %v still ranks %d;"+
			" nine packets buy permanent residency", stored,
			time.Duration(quiet-tNs), ranked)
	}

	// And the consequence: a flood of such entries must not be able to keep a
	// live scanner out of the table.
	for i := 0; i < cfg.MaxSources*2; i++ {
		src := netip.AddrFrom4([4]byte{198, 51, 200, byte(i)})
		for k := 0; k < 12; k++ {
			tNs += ms
			e.Process(synProbe(tNs, src, victim, uint16(20+k)))
		}
	}
	// Much later, a real scan from a new address.
	tNs += uint64(cfg.DecayInterval) * 200
	var ev *ScanEvent
	for i := 0; i < 40 && ev == nil; i++ {
		tNs += ms
		ev = e.Process(synProbe(tNs, attacker, victim, uint16(1000+i)))
	}
	if ev == nil {
		t.Fatal("a scan arriving after the table was filled with long-dead high scorers" +
			" was never reported")
	}
	if ev.Src != attacker {
		t.Fatalf("reported %s, want the scanner %s", ev.Src, attacker)
	}
}

// TestFloodSourcesAreStillEvicted: the protection must not turn into a way to
// pin the table full of junk. A source with one packet is always evictable.
func TestFloodSourcesAreStillEvicted(t *testing.T) {
	h := newFakeHost()
	cfg := testConfig()
	cfg.MaxSources = 64
	e := newTestEngine(t, cfg, h)

	for i := 0; i < 4096; i++ {
		e.Process(synProbe(uint64(i)*ms,
			netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), victim, 80))
	}
	if got := e.Stats().SourcesTracked; got > cfg.MaxSources {
		t.Fatalf("SourcesTracked = %d, exceeds the cap of %d", got, cfg.MaxSources)
	}
	if e.Stats().SourcesEvicted == 0 {
		t.Fatalf("nothing was evicted; the table cannot have stayed bounded")
	}
}

// TestTeardownTrafficIsNotBlockEligible pins that connection teardown is never
// evidence.
//
// FIN|ACK is how every connection in the world ends. Putting it in the
// "anomalous flags" bucket at the highest multiplier in the table, on the
// reasoning that it cannot continue a connection we do not know about, would
// ignore that the connection table is a snapshot up to ten seconds old, so a
// short-lived connection simply is not in it.
//
// Two consequences, both measured against the real engine with FIN|ACK
// counted that way: thirteen ordinary teardown packets from a peer reported
// that peer as running a Maimon scan, and seven forged ones did it
// deliberately, with the victim's own gateway as the easiest target.
// RequireTCPEvidence would not help, because a forged FIN|ACK would count as
// TCP evidence.
func TestTeardownTrafficIsNotBlockEligible(t *testing.T) {
	h := newFakeHost()
	cfg := testConfig()
	cfg.Block.Policy = BlockAuto
	cfg.Block.RequireTCPEvidence = true
	e := newTestEngine(t, cfg, h)

	// A peer closing many short connections that the snapshot missed, aimed at
	// system ports -- the most expensive class, so the worst case.
	var ev *ScanEvent
	for i := 0; i < 200 && ev == nil; i++ {
		ev = e.Process(flagProbe(uint64(i)*ms, attacker, victim, uint16(20+i), TCPFin|TCPAck))
	}

	if ev == nil {
		t.Logf("teardown-shaped traffic never crossed the threshold at all")
		return
	}
	if ev.BlockEligible {
		t.Fatalf("teardown-shaped traffic is block-eligible: %d packets would get %s blocked",
			ev.DistinctPorts, ev.Src)
	}
	if ev.HasTCPEvidence {
		t.Fatalf("a packet carrying ACK must not count as corroborating evidence")
	}
	t.Logf("reported after %d ports (score %d) but not eligible for blocking, as it must be",
		ev.DistinctPorts, ev.Score)
}

// TestSevenPacketGatewayBlockIsClosed: seven forged teardown packets must not
// make a gateway blockable.
func TestSevenPacketGatewayBlockIsClosed(t *testing.T) {
	h := newFakeHost()
	cfg := testConfig()
	cfg.Block.Policy = BlockAuto
	e := newTestEngine(t, cfg, h)

	gateway := netip.MustParseAddr("192.168.1.1")
	for i := 0; i < 7; i++ {
		if ev := e.Process(flagProbe(uint64(i)*ms, gateway, victim, uint16(20+i), TCPFin|TCPAck)); ev != nil {
			if ev.BlockEligible {
				t.Fatalf("seven forged FIN|ACK packets still make %s eligible for blocking", gateway)
			}
		}
	}
	if got := e.Score(gateway); got >= cfg.ScoreThreshold {
		t.Fatalf("score after seven teardown packets = %d, threshold %d", got, cfg.ScoreThreshold)
	}
}

// TestUnambiguousProbesAreStillEvidence: keeping teardown out of the evidence
// must not disarm the gate for traffic that genuinely could not be anything
// but a scan.
func TestUnambiguousProbesAreStillEvidence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint8
	}{
		{"SYN to a closed port", TCPSyn},
		{"FIN alone", TCPFin},
		{"NULL", 0},
		{"Xmas", TCPFin | TCPPsh | TCPUrg},
		{"SYN|FIN", TCPSyn | TCPFin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFakeHost()
			cfg := testConfig()
			cfg.Block.Policy = BlockAuto
			e := newTestEngine(t, cfg, h)

			var ev *ScanEvent
			for i := 0; i < 200 && ev == nil; i++ {
				ev = e.Process(flagProbe(uint64(i)*ms, attacker, victim, uint16(20+i), tc.flags))
			}
			if ev == nil {
				t.Fatalf("no event for %s", tc.name)
			}
			if !ev.HasTCPEvidence || !ev.BlockEligible {
				t.Fatalf("%s must count as evidence: HasTCPEvidence=%v BlockEligible=%v",
					tc.name, ev.HasTCPEvidence, ev.BlockEligible)
			}
		})
	}
}

// TestSlowestFigureHoldsOnTheEngine checks the published slowest-scan figure
// against Engine.Process rather than against the model that computes it. The
// report promises that every interval up to the figure is reported within the
// horizon; a unit test comparing the model with itself could not see intervals
// just under it going unreported -- 17 of them, measured with a probabilistic
// port filter whose false positives dropped a probe's score at random.
func TestSlowestFigureHoldsOnTheEngine(t *testing.T) {
	cfg := testConfig()
	local := netip.MustParseAddr("192.0.2.1")
	src := netip.MustParseAddr("203.0.113.5")
	crosses := func(mk func(uint64, netip.Addr, netip.Addr, uint16) *Probe, base uint16, gap time.Duration) bool {
		e := newTestEngine(t, cfg, newFakeHost())
		for i := 0; ; i++ {
			at := sec + uint64(i)*uint64(gap)
			if time.Duration(at-sec) > detectionHorizon {
				return false
			}
			if e.Process(mk(at, src, local, base+uint16(i))) != nil {
				return true
			}
		}
	}
	for _, r := range []struct {
		name string
		w    uint32
		mk   func(uint64, netip.Addr, netip.Addr, uint16) *Probe
		base uint16
	}{
		{"SYN, system ports", ProbeWeight(PortSystem, multSynClosed), synProbe, 1},
		{"SYN, registered ports", ProbeWeight(PortRegistered, multSynClosed), synProbe, 2000},
		{"SYN, dynamic ports", ProbeWeight(PortDynamic, multSynClosed), synProbe, 50000},
		{"UDP, dynamic ports", ProbeWeight(PortDynamic, multUDP), udpProbe, 50000},
	} {
		fig := cfg.SlowestDetectableScan(r.w).Truncate(time.Second)
		if fig <= 0 {
			t.Fatalf("%s: no figure", r.name)
		}
		// Every 10 ms over the last tenth below the figure, where rounding and
		// step alignment could open a hole.
		for d := fig - fig/10; d <= fig; d += 10 * time.Millisecond {
			if !crosses(r.mk, r.base, d) {
				t.Fatalf("%s: one probe every %v is not reported within %v, though the"+
					" published figure is %v", r.name, d, detectionHorizon, fig)
			}
		}
	}
}

// TestAFirstReportThatCannotBeBlockedDoesNotHideTheScanThatFollows: a source
// reported first on probes anyone can forge -- three ICMP queries, a few UDP
// or ACK probes -- and then sending SYNs is reported again as soon as it can
// be blocked, inside the cooldown and even on ports it had already probed.
// Otherwise the cheap first report would hold back, for the whole cooldown,
// the question or the block the SYN scan earns. And only once.
func TestAFirstReportThatCannotBeBlockedDoesNotHideTheScanThatFollows(t *testing.T) {
	primers := map[string]func(now uint64, p uint16) *Probe{
		"icmp": func(now uint64, p uint16) *Probe {
			return icmpProbe(now, attacker, victim, []uint8{8, 13, 17}[p%3])
		},
		"udp": func(now uint64, p uint16) *Probe { return udpProbe(now, attacker, victim, p) },
		"ack": func(now uint64, p uint16) *Probe { return flagProbe(now, attacker, victim, p, TCPAck) },
	}
	for name, primer := range primers {
		t.Run(name, func(t *testing.T) {
			e := newTestEngine(t, testConfig(), newFakeHost())
			var events []*ScanEvent
			now := sec
			for p := uint16(1); len(events) == 0 && p <= 1024; p++ {
				if ev := e.Process(primer(now, p)); ev != nil {
					events = append(events, ev)
				}
				now += ms
			}
			if len(events) != 1 || events[0].BlockEligible {
				t.Fatalf("the primer gave %d events (eligible: %v); want one that cannot be blocked",
					len(events), len(events) > 0 && events[0].BlockEligible)
			}
			// SYNs on the ports the primer already touched: nothing new but
			// the evidence.
			now += 10 * sec
			for p := uint16(1); p <= 200; p++ {
				if ev := e.Process(synProbe(now, attacker, victim, p)); ev != nil {
					events = append(events, ev)
				}
				now += ms
			}
			events = append(events, e.DrainPending(now+60*sec)...)
			if len(events) != 2 || !events[1].BlockEligible {
				t.Fatalf("after the SYN scan: %d events; want a second one that can be blocked", len(events))
			}
			// Blockable once: more SYNs inside the cooldown say nothing new.
			for p := uint16(1); p <= 200; p++ {
				if ev := e.Process(synProbe(now, attacker, victim, p)); ev != nil {
					t.Fatalf("a third report inside the cooldown: %+v", ev)
				}
				now += ms
			}
		})
	}
}
