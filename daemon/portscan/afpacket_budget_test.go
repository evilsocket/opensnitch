//go:build linux

package portscan

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// TestAFPacketBudgetCapsWhatReachesTheEngine pins the aggregate budget on the
// fallback packet source.
//
// The eBPF path is capped in the kernel -- global_allow at MaxTotalPerSecond,
// before any other map lookup. Without a cap here, with no aggregate cap, no
// per-source cap and no sampling, every frame that passed the ethertype filter
// would cost a recvfrom, a copy and a parse. A remote sender would have a
// direct lever on this host's CPU at roughly one core per gigabit, and this is
// the path a machine lands on by NOT having eBPF, which is the ordinary
// documented case.
func TestAFPacketBudgetCapsWhatReachesTheEngine(t *testing.T) {
	const limit = 100
	w := &atomicWindow{limit: limit}

	// One window: exactly `limit` pass.
	allowed := 0
	for i := 0; i < 10*limit; i++ {
		if w.allow(uint64(i)) { // all within the first second
			allowed++
		}
	}
	if allowed != limit {
		t.Fatalf("%d probes passed a budget of %d in one window", allowed, limit)
	}

	// The next window starts fresh.
	allowed = 0
	base := uint64(time.Second)
	for i := 0; i < 10*limit; i++ {
		if w.allow(base + uint64(i)) {
			allowed++
		}
	}
	if allowed != limit {
		t.Fatalf("%d probes passed in the second window, want %d", allowed, limit)
	}
}

// TestAFPacketBudgetIsNotResetByReordering pins that the window uses the same
// asymmetric rule as the kernel program's window_rolled.
//
// There is one read goroutine per interface, each reading the clock for itself,
// so timestamps step backwards as a matter of course. Treating any backwards
// step as a new window would hand out a fresh budget every time two goroutines
// disagreed by a nanosecond -- which is to say, on a busy multi-interface host,
// no budget at all.
func TestAFPacketBudgetIsNotResetByReordering(t *testing.T) {
	const limit = 50
	w := &atomicWindow{limit: limit}

	// Strictly decreasing timestamps, all inside one window.
	allowed := 0
	start := uint64(10 * time.Millisecond)
	for i := 0; i < 10*limit; i++ {
		if w.allow(start - uint64(i)) {
			allowed++
		}
	}
	if allowed > limit {
		t.Fatalf("%d probes passed a budget of %d using backwards timestamps", allowed, limit)
	}

	// A jump of a full window backwards is a clock anomaly, not reordering, and
	// must roll -- otherwise the window start would sit in the future and this
	// source would be silenced for ever.
	w2 := &atomicWindow{limit: limit}
	for i := 0; i < limit; i++ {
		w2.allow(uint64(10 * time.Second))
	}
	if !w2.allow(uint64(5 * time.Second)) {
		t.Fatal("a timestamp a full window behind did not roll: the source would stay" +
			" budget-starved until the clock caught up")
	}
}

// TestAFPacketBudgetIsSafeUnderConcurrency pins that the shared window holds
// when every interface's read loop hits it at once, which is its normal state.
func TestAFPacketBudgetIsSafeUnderConcurrency(t *testing.T) {
	const (
		limit   = 500
		workers = 8
		each    = 2000
	)
	w := &atomicWindow{limit: limit}

	var mu sync.Mutex
	allowed := 0
	var wg sync.WaitGroup
	for k := 0; k < workers; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			n := 0
			for i := 0; i < each; i++ {
				// All inside one window, with the jitter between goroutines
				// that reading the clock independently produces.
				if w.allow(uint64(k*13 + i)) {
					n++
				}
			}
			mu.Lock()
			allowed += n
			mu.Unlock()
		}(k)
	}
	wg.Wait()

	if allowed > limit {
		t.Fatalf("%d probes passed a budget of %d across %d goroutines: the window"+
			" is not a bound under concurrency", allowed, limit, workers)
	}
}

// TestAFPacketZeroBudgetMeansUnlimited pins the disabled case, so that a
// zero-valued window in a test or a future caller does not silently drop
// everything.
func TestAFPacketZeroBudgetMeansUnlimited(t *testing.T) {
	w := &atomicWindow{}
	for i := 0; i < 1000; i++ {
		if !w.allow(uint64(i)) {
			t.Fatal("a zero limit refused a probe; zero must mean no cap")
		}
	}
}

// newBudgetedAFPacketSource is an AF_PACKET source with its budgets and no
// socket, for the admission decision alone.
func newBudgetedAFPacketSource(total uint32) *AFPacketSource {
	s := &AFPacketSource{}
	s.initBudgets(total)
	return s
}

// TestOnePeerCannotSpendTheAFPacketBudget: with only an aggregate budget,
// taken before the parse, ordinary traffic would spend it. One peer's
// download of 8000 packets a second would let 541 of a concurrent scan's 1000
// probes through, 20000 a second 182, and nothing would say so. Like the eBPF
// path, the fallback holds each source to its own budget, and the aggregate
// is charged only for what that leaves.
func TestOnePeerCannotSpendTheAFPacketBudget(t *testing.T) {
	s := newBudgetedAFPacketSource(afPacketDefaultBudget)
	peer := netip.MustParseAddr("203.0.113.10")
	scanner := netip.MustParseAddr("198.51.100.66")
	admitted := 0
	// One second: 20000 packets from the peer, 200 probes from the scanner
	// interleaved with them.
	for i := 0; i < 20000; i++ {
		now := uint64(i) * 50 * uint64(time.Microsecond)
		s.admit(peer, now)
		if i%100 == 0 && s.admit(scanner, now) {
			admitted++
		}
	}
	if admitted != 200 {
		t.Errorf("%d of the scanner's 200 probes were admitted beside one busy peer", admitted)
	}
	st := s.budgetStats()
	if st["source_rate_limited"] == 0 || st["rate_limited"] != 0 {
		t.Errorf("one peer over its own budget was counted as %v: only source_rate_limited"+
			" may rise, since no other source lost anything", st)
	}
}

// TestForgedSourcesStillHitTheAFPacketAggregate: every forged address is a
// source never seen before, which no per-source budget can bound. The
// aggregate is consulted before such a source is given a budget, as in the
// kernel program, so a flood of them is still capped.
func TestForgedSourcesStillHitTheAFPacketAggregate(t *testing.T) {
	s := newBudgetedAFPacketSource(1000)
	admitted := 0
	for i := 0; i < 20000; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		if s.admit(src, uint64(i)*50*uint64(time.Microsecond)) {
			admitted++
		}
	}
	if admitted != 1000 {
		t.Errorf("a flood of 20000 forged sources in one second admitted %d, want the aggregate's 1000", admitted)
	}
	if st := s.budgetStats(); st["rate_limited"] != 19000 {
		t.Errorf("the aggregate's refusals counted as %v, want rate_limited=19000", st)
	}
}

// holding is the slot src holds, or nil.
func (w *sourceWindows) holding(src netip.Addr) *sourceWindow {
	i, j := w.candidates(src)
	for _, k := range []int{i, j} {
		if w.slots[k].addr == src {
			return &w.slots[k]
		}
	}
	return nil
}

// TestABusyPeerKeepsItsBudgetSlot: the per-source budget table has a fixed
// number of slots. If a source finding its slot held by another took it over
// with a fresh window, two sources sharing a slot would hand each other a new
// budget on every packet: a busy peer beside one quiet colliding source would
// spend the aggregate again, and a concurrent scan would lose most of its
// probes. A slot whose window is still running is not taken over.
func TestABusyPeerKeepsItsBudgetSlot(t *testing.T) {
	// Each table has a random seed, and the peer's slot is the first one the
	// quiet source tries only under some seeds: run on eight tables, so the
	// test does not see its own regression only one time in two.
	exercised := 0
	for i := 0; i < 8; i++ {
		if busyPeerKeepsItsBudgetSlot(t) {
			exercised++
		}
	}
	if exercised < 4 {
		t.Fatalf("only %d of 8 tables had addresses sharing the peer's slots", exercised)
	}
}

// busyPeerKeepsItsBudgetSlot runs the case on one table, and reports false
// when the table has no addresses in the right slots: when the peer's slot
// has a high index, few addresses have it as their first, and that says
// nothing about the code.
func busyPeerKeepsItsBudgetSlot(t *testing.T) bool {
	t.Helper()
	s := newBudgetedAFPacketSource(afPacketDefaultBudget)
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{203, byte(i >> 16), byte(i >> 8), byte(i)}) }
	peer := netip.MustParseAddr("198.51.100.7")
	s.admit(peer, 0)
	// The worst case: a quiet source both of whose slots are taken, the one
	// it tries first by the peer and the other by a second quiet source.
	idx := func(sw *sourceWindow) int {
		for k := range s.sources.slots {
			if &s.sources.slots[k] == sw {
				return k
			}
		}
		return -1
	}
	peerSlot := idx(s.sources.holding(peer))
	ordered := func(a netip.Addr) (int, int) {
		x, y := s.sources.candidates(a)
		return min(x, y), max(x, y)
	}
	var q1, q2 netip.Addr
	other := -1
	for i := 1; !q1.IsValid() && i < 1<<22; i++ {
		if lo, hi := ordered(addr(i)); lo == peerSlot && hi != lo {
			q1, other = addr(i), hi
		}
	}
	for i := 1; q1.IsValid() && !q2.IsValid() && i < 1<<22; i++ {
		if lo, _ := ordered(addr(i)); lo == other && addr(i) != q1 {
			q2 = addr(i)
		}
	}
	if !q1.IsValid() || !q2.IsValid() {
		return false
	}
	peerAdmitted := 0
	for i := 0; i < 3*20000; i++ {
		now := uint64(i) * uint64(time.Second) / 20000
		if i%400 == 0 {
			s.admit(q2, now)
			s.admit(q1, now)
		}
		if s.admit(peer, now) {
			peerAdmitted++
		}
	}
	st := s.budgetStats()
	if peerAdmitted > 3*afPacketPerSourceBudget || st["rate_limited"] != 0 {
		t.Fatalf("a busy peer sharing its slot with quiet sources was admitted %d times in 3 s"+
			" (its budget allows %d), %v", peerAdmitted, 3*afPacketPerSourceBudget, st)
	}
	return true
}

// TestASourceWithoutASlotStillHasABudget: a source both of whose slots are
// held by running sources takes neither. Admitted on the aggregate budget
// alone, with no per-source cap, a busy peer in that position would spend the
// aggregate, and a concurrent scan would lose its probes. Sources without a
// slot share one per-source budget, counted and reported like the aggregate
// since it is shared, and the sources holding the slots keep them.
func TestASourceWithoutASlotStillHasABudget(t *testing.T) {
	s := newBudgetedAFPacketSource(afPacketDefaultBudget)
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{203, byte(i >> 16), byte(i >> 8), byte(i)}) }
	peer := netip.MustParseAddr("198.51.100.7")
	px, py := s.sources.candidates(peer)
	if px == py {
		t.Skip("the peer's two candidates coincide under this seed")
	}
	var holders []netip.Addr
	for _, slot := range []int{px, py} {
		for i := 1; i < 1<<22; i++ {
			if x, y := s.sources.candidates(addr(i)); min(x, y) == slot && x != y {
				holders = append(holders, addr(i))
				break
			}
		}
	}
	if len(holders) != 2 {
		t.Fatal("found no addresses to hold the peer's slots")
	}
	peerAdmitted := 0
	for i := 0; i < 3*20000; i++ {
		now := uint64(i) * uint64(time.Second) / 20000
		if i%400 == 0 {
			for _, h := range holders {
				s.admit(h, now)
			}
		}
		if s.admit(peer, now) {
			peerAdmitted++
		}
	}
	for _, h := range holders {
		if s.sources.holding(h) == nil {
			t.Errorf("%s lost its slot to a source that had none", h)
		}
	}
	if s.sources.holding(peer) != nil {
		t.Fatal("the peer took a slot held by a running source")
	}
	if peerAdmitted > 3*afPacketPerSourceBudget {
		t.Fatalf("a busy peer with no slot was admitted %d times in 3 s (a source's budget"+
			" allows %d), %v", peerAdmitted, 3*afPacketPerSourceBudget, s.budgetStats())
	}
}

// TestTwoReadLoopsDoNotDeadlockOnSlots: one read loop runs per interface, so
// admit runs concurrently, and it holds two slot locks at once. Two sources
// whose candidate slots are the same pair in opposite order would deadlock
// each other if the locks were not taken in one fixed order.
func TestTwoReadLoopsDoNotDeadlockOnSlots(t *testing.T) {
	s := newBudgetedAFPacketSource(0)
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}) }
	type pair struct{ i, j int }
	seen := map[pair]netip.Addr{}
	var a, b netip.Addr
	for n := 1; n < 1<<22 && !a.IsValid(); n++ {
		x := addr(n)
		i, j := s.sources.candidates(x)
		if i == j {
			continue
		}
		if y, ok := seen[pair{j, i}]; ok {
			a, b = y, x
		}
		seen[pair{i, j}] = x
	}
	if !a.IsValid() {
		t.Fatal("found no two sources with crossed slots")
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	for _, src := range []netip.Addr{a, b} {
		wg.Add(1)
		go func(src netip.Addr) {
			defer wg.Done()
			for k := 0; k < 300_000; k++ {
				s.admit(src, uint64(k))
			}
		}(src)
	}
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("admit deadlocked on %v and %v, whose slots are crossed", a, b)
	}
}

// TestAnEndedWindowFreesItsSlot: a slot is held only while its source's
// window runs. Once a second has passed without it, a new source that finds
// both its slots taken by quiet sources gets one; otherwise a table filled
// once would leave every later source on the shared budget for good.
func TestAnEndedWindowFreesItsSlot(t *testing.T) {
	s := newBudgetedAFPacketSource(afPacketDefaultBudget)
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{203, byte(i >> 16), byte(i >> 8), byte(i)}) }
	newcomer := netip.MustParseAddr("192.0.2.9")
	i, j := s.sources.candidates(newcomer)
	var holders []netip.Addr
	for _, slot := range []int{min(i, j), max(i, j)} {
		for n := 1; n < 1<<22; n++ {
			if x, y := s.sources.candidates(addr(n)); min(x, y) == slot && x != y {
				holders = append(holders, addr(n))
				break
			}
		}
	}
	if i == j || len(holders) != 2 {
		t.Skip("no two distinct holders under this seed")
	}
	for _, h := range holders {
		s.admit(h, 0)
	}
	s.admit(newcomer, uint64(100*time.Millisecond))
	if s.sources.holding(newcomer) != nil {
		t.Fatal("a source took a slot whose window was still running")
	}
	s.admit(newcomer, uint64(2*time.Second))
	if s.sources.holding(newcomer) == nil {
		t.Fatal("two seconds after its holders went quiet, no slot was free for a new source")
	}
}

// TestASourceWithASlotIsNotChargedForTheSourcesWithout: a source without a
// slot is refused by the shared budget before it is charged to the
// aggregate. Charged first, a busy peer without a slot spent the aggregate on
// packets the shared budget then refused, and a scanner in its own slot fell
// to 123 of 600 probes.
func TestASourceWithASlotIsNotChargedForTheSourcesWithout(t *testing.T) {
	for n := 0; n < 8; n++ {
		s := newBudgetedAFPacketSource(afPacketDefaultBudget)
		addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{203, byte(i >> 16), byte(i >> 8), byte(i)}) }
		peer := netip.MustParseAddr("198.51.100.7")
		px, py := s.sources.candidates(peer)
		if px == py {
			continue
		}
		var holders []netip.Addr
		for _, slot := range []int{px, py} {
			for i := 1; i < 1<<22; i++ {
				if x, y := s.sources.candidates(addr(i)); min(x, y) == slot && x != y {
					holders = append(holders, addr(i))
					break
				}
			}
		}
		scan := netip.MustParseAddr("192.0.2.77")
		got, all := 0, 0
		for i := 0; i < 3*20000; i++ {
			now := uint64(i) * uint64(time.Second) / 20000
			if i%400 == 0 {
				for _, h := range holders {
					s.admit(h, now)
				}
			}
			if i%100 == 0 {
				all++
				if s.admit(scan, now) {
					got++
				}
			}
			s.admit(peer, now)
		}
		if got != all {
			t.Fatalf("a 200-probe/s scanner beside a busy peer without a slot: %d of %d admitted, %v",
				got, all, s.budgetStats())
		}
	}
}

// TestAnActiveSourceKeepsItsSlotAcrossItsWindow: a slot counted as in use
// only while its source's one-second window ran, and the window rolls on the
// source's next packet. A newcomer arriving just after the second ended,
// before that packet, took the slot of a source sending twenty thousand
// frames a second, in 3993 tables of 4000 measured. A slot is
// in use while its source has sent anything in the last second.
func TestAnActiveSourceKeepsItsSlotAcrossItsWindow(t *testing.T) {
	s := newBudgetedAFPacketSource(afPacketDefaultBudget)
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{203, byte(i >> 16), byte(i >> 8), byte(i)}) }
	peer := netip.MustParseAddr("198.51.100.7")
	s.admit(peer, 0)
	held := s.sources.holding(peer)
	var newcomer netip.Addr
	for i := 1; i < 1<<22 && !newcomer.IsValid(); i++ {
		x, y := s.sources.candidates(addr(i))
		if x != y && (&s.sources.slots[min(x, y)] == held) {
			newcomer = addr(i)
		}
	}
	if !newcomer.IsValid() {
		t.Fatal("found no address whose first slot is the peer's")
	}
	for k := 1; k < 1000; k++ {
		s.admit(peer, uint64(k)*uint64(time.Millisecond))
	}
	// Just past the second the peer's window opened, before its next frame.
	s.admit(newcomer, uint64(time.Second)+uint64(500*time.Microsecond))
	if s.sources.holding(peer) != held {
		t.Fatal("a source sending every millisecond lost its slot at the end of its window")
	}
}

// TestLoopbackHasALinkHeader: loopback has an all-zero hardware address, which
// net.Interface reports as empty, like a tun device's. Its frames carry an
// Ethernet header all the same; classed as headerless, they would be read from
// the wrong offset by the eBPF program and every probe on it lost.
func TestLoopbackHasALinkHeader(t *testing.T) {
	cases := []struct {
		name string
		ifi  net.Interface
		want bool
	}{
		{"ethernet", net.Interface{HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}, true},
		{"loopback", net.Interface{Flags: net.FlagLoopback | net.FlagUp}, true},
		{"tun", net.Interface{Flags: net.FlagPointToPoint | net.FlagUp}, false},
	}
	for _, c := range cases {
		if got := hasLinkHeader(c.ifi); got != c.want {
			t.Errorf("%s: hasLinkHeader = %v, want %v", c.name, got, c.want)
		}
	}
}
