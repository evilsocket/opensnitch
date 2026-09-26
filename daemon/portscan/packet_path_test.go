package portscan

import (
	"net/netip"
	"sort"
	"testing"
	"time"
)

// slowBlocker is a firewall backend that takes a long time, as a real one does
// under load: every nftables operation is a netlink round trip, and a release
// pass holds its lock for the whole of it.
type slowBlocker struct {
	*fakeBlocker
	delay time.Duration
}

func (s *slowBlocker) Block(a netip.Addr) error {
	time.Sleep(s.delay)
	return s.fakeBlocker.Block(a)
}

func (s *slowBlocker) Unblock(a netip.Addr) error {
	time.Sleep(s.delay)
	return s.fakeBlocker.Unblock(a)
}

// TestPacketPathDoesNotWaitForTheFirewall pins that the cost of onProbe is
// independent of how slow the enforcement backend is.
//
// onProbe runs on the single goroutine that drains the kernel's ring buffer. If
// it called handleEvent inline, a crossing would carry a full netlink round
// trip on that goroutine: measured that way against a real nftables, 2.4
// microseconds for an ordinary probe against 2853 microseconds at the median
// -- 10618 at worst -- for one that installed a block. While that ran, nothing
// would drain the ring, so the kernel would drop probes: the feature would
// blind itself at the exact moment it had decided someone was scanning.
//
// The backend here is made 50 ms slow, which is far beyond anything real. If
// onProbe is still fast, it is not waiting for it.
func TestPacketPathDoesNotWaitForTheFirewall(t *testing.T) {
	const backendDelay = 50 * time.Millisecond

	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
		o.Config.ReportCooldown = 0
		o.NewBlocker = func(time.Duration) (Blocker, error) {
			return &slowBlocker{fakeBlocker: newFakeBlocker(), delay: backendDelay}, nil
		}
	})

	// Feed enough distinct sources that many of them cross.
	var took []time.Duration
	base := h.src.NowNs()
	const sources = 12
	for s := 0; s < sources; s++ {
		src := srcN(s)
		for k := 0; k < 11; k++ {
			p := synProbe(base+uint64(s*20+k)*ms, src, netip.MustParseAddr("127.0.0.1"), uint16(21+k))
			t0 := time.Now()
			h.m.onProbe(p)
			took = append(took, time.Since(t0))
		}
	}

	sort.Slice(took, func(i, j int) bool { return took[i] < took[j] })
	worst := took[len(took)-1]
	median := took[len(took)/2]
	t.Logf("onProbe over %d probes: median %v, worst %v (backend delay %v)",
		len(took), median, worst, backendDelay)

	// Generous: a tenth of one backend operation. Inline, the crossing probes
	// would each have cost a full backendDelay.
	if limit := backendDelay / 10; worst > limit {
		t.Fatalf("onProbe took %v at worst with a %v backend: the packet path is"+
			" still waiting for the firewall", worst, backendDelay)
	}

	// And the work really did happen, just elsewhere: draining the queue does
	// pay the backend cost.
	t0 := time.Now()
	h.m.drainEvents()
	if elapsed := time.Since(t0); elapsed < backendDelay {
		t.Fatalf("draining the queue took %v, less than one backend operation (%v):"+
			" no crossing reached the firewall, so this test proved nothing",
			elapsed, backendDelay)
	}
}

// TestCrossingsAreDroppedRatherThanQueuedForever pins the other half of the
// trade: the queue is bounded, so a backend that cannot keep up costs events
// rather than stalling the reader -- and the drops are counted, because a user
// whose policy is "auto" would otherwise believe every detected scanner was
// blocked.
func TestCrossingsAreDroppedRatherThanQueuedForever(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
		o.Config.ReportCooldown = 0
		o.Config.AlertsPerMinute = 600
	})

	// Never drain: the queue fills and then must refuse, not grow.
	base := h.src.NowNs()
	for s := 0; s < eventQueueDepth*3; s++ {
		src := srcN(s)
		for k := 0; k < 11; k++ {
			h.m.onProbe(synProbe(base+uint64(s*20+k)*ms, src,
				netip.MustParseAddr("127.0.0.1"), uint16(21+k)))
		}
	}

	if n := len(h.m.events); n > eventQueueDepth {
		t.Fatalf("the queue holds %d events, above its bound of %d", n, eventQueueDepth)
	}
	if h.m.eventsDropped.Load() == 0 {
		t.Fatal("the queue filled but nothing was counted as dropped: a user on policy" +
			" \"auto\" would believe every detected scanner had been blocked")
	}
	t.Logf("queue depth %d, dropped %d", len(h.m.events), h.m.eventsDropped.Load())
}
