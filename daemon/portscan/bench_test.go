package portscan

import (
	"net/netip"
	"runtime"
	"testing"
	"time"
)

// The feature was asked for on the condition that it be cheap. That is a claim
// about numbers, so this file produces numbers rather than adjectives.
//
// Two properties are load-bearing and are asserted as tests, not merely
// measured:
//
//   - the packet path allocates nothing. An allocation per packet would put the
//     garbage collector on the path a scanner controls the rate of;
//   - the cost per packet does not grow with how much the source has already
//     done. This is the flaw in flowhawk, whose per-packet path walks every port
//     it has recorded for the source (engine.go:197-201), and in Portmaster,
//     which linearly scans its blockedPorts slice on every packet. Both get
//     slower the longer a scan runs, which is precisely backwards.
//
// Run the measurements with:
//
//	go test -run '^$' -bench . -benchmem ./portscan/

// benchHost is a HostInfo that allocates nothing.
//
// fakeHost builds its map keys with fmt.Sprintf, which is perfectly fine for
// correctness tests and completely wrong here: it would put eight allocations
// per packet into the measurement and hide whatever the engine itself does.
// The production SystemHostInfo answers from comparable struct keys, exactly as
// this does.
type benchHost struct {
	listening bool
	connected bool
	onLink    bool
	exempt    bool
}

func (h *benchHost) IsLocalUnicast(a netip.Addr) bool { return !a.IsMulticast() }
func (h *benchHost) IsListening(uint8, uint16) bool   { return h.listening }
func (h *benchHost) HasConnection(*Probe) bool        { return h.connected }
func (h *benchHost) IsOnLink(netip.Addr) bool         { return h.onLink }
func (h *benchHost) IsExempt(netip.Addr) bool         { return h.exempt }

func benchEngine(b *testing.B) *Engine {
	b.Helper()
	cfg := testConfig()
	cfg.ScoreThreshold = 1 << 20 // never report: this measures the common path
	cfg.MaxSources = 4096
	e, err := NewEngine(cfg, &benchHost{}, 0)
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}
	return e
}

// BenchmarkEngineProcessSYN is the ordinary case: one SYN to a closed port.
func BenchmarkEngineProcessSYN(b *testing.B) {
	e := benchEngine(b)
	p := synProbe(0, attacker, victim, 1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.TimeNs = uint64(i) * uint64(time.Microsecond)
		p.DstPort = uint16(i)
		e.Process(p)
	}
}

// BenchmarkEngineProcessManySources measures the cost when the source table is
// full and every packet is from a different address, which is what a
// spoofed-source or decoy scan produces.
func BenchmarkEngineProcessManySources(b *testing.B) {
	e := benchEngine(b)
	srcs := make([]netip.Addr, 4096)
	for i := range srcs {
		srcs[i] = netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
	}
	p := synProbe(0, attacker, victim, 1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.TimeNs = uint64(i) * uint64(time.Microsecond)
		p.Src = srcs[i%len(srcs)]
		p.DstPort = uint16(i)
		e.Process(p)
	}
}

// BenchmarkEngineProcessFiltered measures a packet the engine rejects
// structurally -- the cheap path that flood traffic must take.
func BenchmarkEngineProcessFiltered(b *testing.B) {
	e := benchEngine(b)
	p := synProbe(0, attacker, victim, 67) // an excluded discovery port

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.TimeNs = uint64(i) * uint64(time.Microsecond)
		e.Process(p)
	}
}

func BenchmarkEngineProcessUDP(b *testing.B) {
	e := benchEngine(b)
	p := udpProbe(0, attacker, victim, 1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.TimeNs = uint64(i) * uint64(time.Microsecond)
		p.DstPort = uint16(i)
		e.Process(p)
	}
}

// BenchmarkParseEthernet measures the AF_PACKET path's per-frame parsing, which
// is the work the eBPF path moves into the kernel.
func BenchmarkParseEthernet(b *testing.B) {
	frames := map[string][]byte{
		"ipv4-tcp": ethFrame(ethTypeIPv4, nil,
			ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(40000, 22, TCPSyn, 8))),
		"ipv6-tcp": ethFrame(ethTypeIPv6, nil,
			ipv6Packet(ProtoTCP, v6src, v6dst, tcpHeader(40000, 22, TCPSyn, 8))),
		"ipv6-ext-chain": ethFrame(ethTypeIPv6, nil,
			ipv6Packet(ipv6ExtHopByHop, v6src, v6dst,
				append(extHeader(ipv6ExtDestOpts, 8),
					append(extHeader(ProtoTCP, 16), tcpHeader(40000, 22, TCPSyn, 8)...)...))),
		"vlan-ipv4-udp": ethFrame(ethTypeIPv4, []uint16{100},
			ipv4Packet(ProtoUDP, v4src, v4dst, 0, false, udpHeader(40000, 53))),
	}

	for name, frame := range frames {
		b.Run(name, func(b *testing.B) {
			var p Probe
			b.SetBytes(int64(len(frame)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p = Probe{}
				_ = ParseEthernet(frame, &p)
			}
			_ = p
		})
	}
}

// BenchmarkFullAFPacketPath is parse plus judge: everything the userspace
// fallback does per frame.
func BenchmarkFullAFPacketPath(b *testing.B) {
	e := benchEngine(b)
	// The engine must accept the destination, so use the addresses the fake
	// host treats as local.
	frame := ethFrame(ethTypeIPv4, nil,
		ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(40000, 22, TCPSyn, 8)))

	var p Probe // one per loop, as AFPacketSource.readLoop does
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p = Probe{}
		if err := ParseEthernet(frame, &p); err != nil {
			b.Fatalf("ParseEthernet: %v", err)
		}
		p.TimeNs = uint64(i) * uint64(time.Microsecond)
		p.DstPort = uint16(i)
		e.Process(&p)
	}
}

func BenchmarkSourceStateAddPort(b *testing.B) {
	st := &sourceState{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.addPort(ProtoTCP, uint16(i))
	}
}

// ---------------------------------------------------------------------------
// the two properties that are asserted, not merely measured
// ---------------------------------------------------------------------------

// TestPacketPathDoesNotAllocate: an allocation per packet would hand a scanner
// control over how often the garbage collector runs.
func TestPacketPathDoesNotAllocate(t *testing.T) {
	cfg := testConfig()
	cfg.ScoreThreshold = 1 << 20
	e, err := NewEngine(cfg, &benchHost{}, 0)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	frame := ethFrame(ethTypeIPv4, nil,
		ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(40000, 22, TCPSyn, 8)))

	// One Probe for the whole loop, which is what AFPacketSource.readLoop and
	// EbpfSource.Run do. The first Process also inserts the source into the
	// table, which legitimately allocates once per source rather than once per
	// packet, so it happens before the measurement starts.
	var p Probe
	_ = ParseEthernet(frame, &p)
	e.Process(&p)

	n := testing.AllocsPerRun(2000, func() {
		p = Probe{}
		_ = ParseEthernet(frame, &p)
		e.Process(&p)
	})
	if n > 0 {
		t.Fatalf("the packet path allocates %.1f objects per packet, want 0", n)
	}
}

// TestReusedProbeIsFullyReset guards the price of that reuse.
//
// Sharing one Probe across packets is what makes the path allocation-free, and
// it is also how a flag from the previous packet gets attributed to this one --
// which would be a false accusation, not merely a bug. Both fill paths assign
// the whole struct so the reset is total by construction; this checks it.
func TestReusedProbeIsFullyReset(t *testing.T) {
	dirty := Probe{
		TimeNs: 1 << 40, Src: netip.MustParseAddr("203.0.113.1"),
		Dst: netip.MustParseAddr("203.0.113.2"), SrcMAC: [6]byte{9, 9, 9, 9, 9, 9},
		HasMAC: true, Proto: ProtoUDP, TCPFlags: 0xff, TCPFlagsValid: true,
		SrcPort: 9999, DstPort: 9999, IfaceIndex: 99,
		Anomalies: AnomalyFragment | AnomalyExtHeaderChain | AnomalyTruncated | AnomalyNoTCPOptions,
	}

	// The shape of the AF_PACKET loop: whole-struct assignment, then parse.
	p := dirty
	p = Probe{TimeNs: 42, IfaceIndex: 3}
	frame := ethFrame(ethTypeIPv4, nil,
		ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(40000, 22, TCPFin, 8)))
	if err := ParseEthernet(frame, &p); err != nil {
		t.Fatalf("ParseEthernet: %v", err)
	}

	if p.Anomalies != 0 {
		t.Errorf("anomalies from the previous packet survived: %#x", p.Anomalies)
	}
	if p.Proto != ProtoTCP || p.TCPFlags != TCPFin || p.DstPort != 22 || p.SrcPort != 40000 {
		t.Errorf("stale transport fields: proto %d flags %#x ports %d -> %d",
			p.Proto, p.TCPFlags, p.SrcPort, p.DstPort)
	}
	if p.Src != v4src || p.Dst != v4dst {
		t.Errorf("stale addresses: %s -> %s", p.Src, p.Dst)
	}
	if p.SrcMAC == ([6]byte{9, 9, 9, 9, 9, 9}) {
		t.Errorf("the previous packet's MAC survived")
	}
	if p.TimeNs != 42 || p.IfaceIndex != 3 {
		t.Errorf("the loop's own fields were lost: t=%d iface=%d", p.TimeNs, p.IfaceIndex)
	}

	// A frame the parser rejects must not leave the previous packet's fields
	// behind for the caller to act on either.
	p = dirty
	p = Probe{}
	if err := ParseEthernet(ethFrame(0x0806, nil, make([]byte, 28)), &p); err == nil {
		t.Fatalf("ARP should not parse")
	}
	if p.Src.IsValid() || p.DstPort != 0 || p.Anomalies != 0 {
		t.Fatalf("a rejected frame left usable-looking fields behind: %+v", p)
	}
}

// TestPerPacketCostDoesNotGrowWithHistory is the property that separates this
// from flowhawk and Portmaster: a scan must not become more expensive to observe
// the longer it runs.
//
// The comparison is between a source that has just started and one that has
// already touched sixty thousand ports. The bound is deliberately loose -- this
// is a shared, noisy machine and the point is the shape of the curve, not a
// figure to defend to two decimals -- but a linear scan over recorded ports
// would exceed it by orders of magnitude.
func TestPerPacketCostDoesNotGrowWithHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("timing comparison; skipped under -short")
	}
	if raceEnabled {
		t.Skip("the race detector costs an order of magnitude; the figure would mean nothing")
	}

	measure := func(warmupPorts int) time.Duration {
		res := testing.Benchmark(func(b *testing.B) {
			cfg := testConfig()
			cfg.ScoreThreshold = 1 << 20
			e, err := NewEngine(cfg, &benchHost{}, 0)
			if err != nil {
				b.Fatalf("NewEngine: %v", err)
			}
			p := synProbe(0, attacker, victim, 1)
			for i := 0; i < warmupPorts; i++ {
				p.TimeNs = uint64(i) * uint64(time.Nanosecond)
				p.DstPort = uint16(i)
				e.Process(p)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p.TimeNs = uint64(warmupPorts+i) * uint64(time.Nanosecond)
				p.DstPort = uint16(i)
				e.Process(p)
			}
		})
		return time.Duration(res.NsPerOp())
	}

	cold := measure(0)
	warm := measure(60000)
	t.Logf("cost per probe: %v with no history, %v after 60000 ports", cold, warm)

	if cold <= 0 {
		t.Fatalf("the benchmark produced no timing")
	}
	if warm > 4*cold {
		t.Fatalf("cost per probe grew from %v to %v after 60000 ports: the work is not bounded", cold, warm)
	}
}

// TestStateSizePerSourceIsBounded pins the memory side of the same property.
// scanlogd is the only one of the surveyed tools that bounds its state; this
// makes the bound explicit and checkable.
func TestStateSizePerSourceIsBounded(t *testing.T) {
	cfg := testConfig()
	cfg.ScoreThreshold = 1 << 20
	cfg.MaxSources = 64
	e, err := NewEngine(cfg, &benchHost{}, 0)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// One source, every port there is, several times over.
	p := synProbe(0, attacker, victim, 1)
	for round := 0; round < 3; round++ {
		for port := 0; port <= 0xffff; port++ {
			p.TimeNs = uint64(round*0x10000+port) * uint64(time.Nanosecond)
			p.DstPort = uint16(port)
			e.Process(p)
		}
	}

	if got := e.Stats().SourcesTracked; got != 1 {
		t.Fatalf("SourcesTracked = %d, want 1", got)
	}

	// And the table itself never exceeds its cap, whatever is thrown at it.
	for i := 0; i < 5000; i++ {
		q := synProbe(uint64(i)*uint64(time.Microsecond),
			netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), victim, uint16(i))
		q.Src = netip.AddrFrom4([4]byte{byte(203 + i%2), 0, byte(i >> 8), byte(i)})
		e.Process(q)
	}
	if got := e.Stats().SourcesTracked; got > cfg.MaxSources {
		t.Fatalf("SourcesTracked = %d, exceeds the cap of %d", got, cfg.MaxSources)
	}
}

// TestReportPerProbeBudget turns the benchmark into a statement an operator can
// act on: how many packets per second one core can absorb.
//
// It asserts only a floor low enough to be meaningless as a performance claim
// and high enough to catch a catastrophic regression -- the number in the log
// is the useful part.
func TestReportPerProbeBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement; skipped under -short")
	}
	if raceEnabled {
		t.Skip("the race detector costs an order of magnitude; the figure would mean nothing")
	}

	res := testing.Benchmark(func(b *testing.B) {
		cfg := testConfig()
		cfg.ScoreThreshold = 1 << 20
		e, err := NewEngine(cfg, &benchHost{}, 0)
		if err != nil {
			b.Fatalf("NewEngine: %v", err)
		}
		frame := ethFrame(ethTypeIPv4, nil,
			ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(40000, 22, TCPSyn, 8)))
		var p Probe // one per loop, as the real read loop does
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p = Probe{}
			_ = ParseEthernet(frame, &p)
			p.TimeNs = uint64(i) * uint64(time.Microsecond)
			p.DstPort = uint16(i)
			e.Process(&p)
		}
	})

	ns := res.NsPerOp()
	if ns <= 0 {
		t.Fatalf("the benchmark produced no timing")
	}
	perSecond := int64(time.Second) / ns
	t.Logf("AF_PACKET path: %d ns per frame, about %d frames/s on one core, %d B/op",
		ns, perSecond, res.AllocedBytesPerOp())

	if perSecond < 100_000 {
		t.Fatalf("only %d frames/s per core: something has regressed badly", perSecond)
	}
}

// BenchmarkEngineParallelSameSource and BenchmarkEngineParallelManySources
// measure lock contention on the packet path.
//
// A single engine-wide mutex covering all of Process made the cost per probe
// RISE by 86% going from one core to four: not merely a failure to scale, but a
// regression under contention, on a path whose rate an attacker chooses.
//
//	go test -run '^$' -bench 'Parallel' -cpu 1,2,4 ./portscan/
func BenchmarkEngineParallelSameSource(b *testing.B) {
	e := benchEngine(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		p := synProbe(0, attacker, victim, 1)
		i := uint64(0)
		for pb.Next() {
			i++
			p.TimeNs = i * uint64(time.Microsecond)
			p.DstPort = uint16(i)
			e.Process(p)
		}
	})
}

// BenchmarkEngineParallelManySources is the shape that matters most: a flood of
// forged sources, which is what an attacker actually sends and what the shards
// exist to spread.
func BenchmarkEngineParallelManySources(b *testing.B) {
	e := benchEngine(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		p := synProbe(0, attacker, victim, 1)
		i := uint64(0)
		for pb.Next() {
			i++
			p.TimeNs = i * uint64(time.Microsecond)
			p.Src = netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
			p.DstPort = uint16(i)
			e.Process(p)
		}
	})
}

// TestEngineScalesWithCores asserts that the
// cost per probe must not RISE when cores are added.
//
// The bound is loose on purpose -- this is a shared, noisy machine and the
// point is the direction of the curve, not a figure to defend. A single global
// lock produced +86%; anything near that fails here.
func TestEngineScalesWithCores(t *testing.T) {
	if testing.Short() {
		t.Skip("timing comparison; skipped under -short")
	}
	if raceEnabled {
		t.Skip("the race detector serialises far more than the engine does")
	}
	if runtime.NumCPU() < 2 {
		t.Skip("needs at least two cores to say anything")
	}

	measure := func(procs int) time.Duration {
		res := testing.Benchmark(func(b *testing.B) {
			old := runtime.GOMAXPROCS(procs)
			defer runtime.GOMAXPROCS(old)
			e := benchEngine(b)
			b.SetParallelism(procs)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				p := synProbe(0, attacker, victim, 1)
				i := uint64(0)
				for pb.Next() {
					i++
					p.TimeNs = i * uint64(time.Microsecond)
					p.Src = netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
					p.DstPort = uint16(i)
					e.Process(p)
				}
			})
		})
		return time.Duration(res.NsPerOp())
	}

	one := measure(1)
	many := measure(runtime.NumCPU())
	t.Logf("cost per probe: %v on 1 core, %v on %d cores", one, many, runtime.NumCPU())

	if one <= 0 || many <= 0 {
		t.Fatalf("the benchmark produced no timing")
	}
	// Allow some rise -- shards do not remove every shared cache line -- but
	// nothing like the serialisation a single lock produced.
	if many > one*3/2 {
		t.Fatalf("cost per probe rose from %v to %v when going from 1 to %d cores: the engine is serialising",
			one, many, runtime.NumCPU())
	}
}

// TestShardSelectionIsSeeded: with a fixed hash an attacker computes offline a
// set of addresses that all land in one shard, and evicts a real scanner from
// it with MaxSources/shards forged sources instead of MaxSources -- sixteen
// times cheaper than the flood evictOne exists to make expensive.
func TestShardSelectionIsSeeded(t *testing.T) {
	cfg := testConfig()
	a := netip.MustParseAddr("192.0.2.66")

	seen := map[int]bool{}
	for i := 0; i < 32; i++ {
		e, err := NewEngine(cfg, newFakeHost(), 0)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		target := e.table.shardFor(a)
		for idx, s := range e.table.shards {
			if s == target {
				seen[idx] = true
			}
		}
	}
	if len(e2eShardCount(cfg)) > 1 && len(seen) < 2 {
		t.Fatalf("the same address landed in the same shard across %d engines: the hash is not seeded", 32)
	}
	t.Logf("%s landed in %d distinct shard indices across 32 engines", a, len(seen))
}

// e2eShardCount reports how many shards a configuration produces, so the test
// above can skip its assertion on a build where there is only one.
func e2eShardCount(cfg Config) []*sourceTable {
	return newShardedTable(cfg.MaxSources, uint64(cfg.DecayInterval), cfg.ScoreThreshold, 1).shards
}

// TestShardsPreserveTheGlobalCap: splitting the table must not raise the total
// number of tracked sources beyond what MaxSources promises.
func TestShardsPreserveTheGlobalCap(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSources = 1024
	e := newTestEngine(t, cfg, newFakeHost())

	for i := 0; i < 50000; i++ {
		e.Process(synProbe(uint64(i)*ms,
			netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), victim, uint16(i)))
	}
	got := e.Stats().SourcesTracked
	// Per-shard capacity is rounded up, so the sum can exceed MaxSources by at
	// most one entry per shard.
	if got > cfg.MaxSources+len(e.table.shards) {
		t.Fatalf("SourcesTracked = %d, well past the cap of %d", got, cfg.MaxSources)
	}
	t.Logf("%d sources tracked across %d shards, cap %d", got, len(e.table.shards), cfg.MaxSources)
}

// TestShardDistributionIsEven is the regression test for a hash that collapsed.
//
// An uneven split is not a performance detail: a shard holding everything makes
// the effective table N times smaller, so the forged-source flood that evictOne
// exists to make expensive becomes N times cheaper again. The first version of
// shardFor put all 50000 addresses of a /16 into one of eight shards.
func TestShardDistributionIsEven(t *testing.T) {
	const addrs = 50000
	tbl := newShardedTable(4096, uint64(10*time.Second), 100, 0x1234567890abcdef)
	if len(tbl.shards) < 2 {
		t.Skip("only one shard at this capacity")
	}
	expected := addrs / len(tbl.shards)

	check := func(name string, mk func(int) netip.Addr) {
		t.Helper()
		counts := make(map[*sourceTable]int, len(tbl.shards))
		for i := 0; i < addrs; i++ {
			counts[tbl.shardFor(mk(i))]++
		}
		if len(counts) != len(tbl.shards) {
			t.Fatalf("%s: only %d of %d shards were used", name, len(counts), len(tbl.shards))
		}
		for _, n := range counts {
			if n < expected/2 || n > expected*2 {
				t.Fatalf("%s: a shard holds %d of %d addresses, expected about %d: the hash is not spreading",
					name, n, addrs, expected)
			}
		}
	}

	check("ipv4", func(i int) netip.Addr {
		return netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
	})
	// IPv6 varies in different bytes from a v4-mapped address, so it exercises
	// the other half of the fold.
	check("ipv6", func(i int) netip.Addr {
		var b [16]byte
		b[0], b[1] = 0x20, 0x01
		b[14], b[15] = byte(i>>8), byte(i)
		return netip.AddrFrom16(b)
	})
}
