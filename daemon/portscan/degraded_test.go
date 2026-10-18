//go:build linux

package portscan

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestEveryDegradationIsMarked drives the real error paths and requires each
// one to produce an error the daemon will surface.
//
// Deciding that by matching literal substrings against the message text would
// not hold: the messages drift away from such a list and nothing fails.
// Measured with a list of six substrings, seven of seven degradations were
// classified as ordinary noise and never reached the user -- including the one
// saying detection was blind, and the one saying a rule had been left in the
// firewall that the daemon could no longer remove.
//
// The point of this test is that it collects the errors from the code that
// raises them, never from a copied string: a message reworded tomorrow is still
// checked, and a NEW degradation added without the marker fails here rather than
// going silent in production.
func TestEveryDegradationIsMarked(t *testing.T) {
	collect := func(run func(report func(error))) []error {
		var got []error
		run(func(e error) { got = append(got, e) })
		return got
	}

	cases := []struct {
		name string
		run  func(report func(error))
	}{
		{
			name: "the host has no addresses, so nothing can be detected",
			run: func(report func(error)) {
				m := &Monitor{onError: report, host: &SystemHostInfo{
					localAddrs: map[netip.Addr]bool{},
				}}
				m.checkHostView()
			},
		},
		{
			name: "crossings were dropped because the firewall could not keep up",
			run: func(report func(error)) {
				m := &Monitor{onError: report}
				m.eventsDropped.Store(5)
				m.checkDroppedEvents()
			},
		},
		{
			name: "a block could not be released",
			run: func(report func(error)) {
				b := &failingUnblocker{fakeBlocker: newFakeBlocker(), fail: true}
				m, err := NewBlockManager(b, BlockConfig{Duration: time.Hour, MaxBlockedSources: 4},
					func(netip.Addr) bool { return false })
				if err != nil {
					t.Fatal(err)
				}
				m.SetOnError(report)
				addr := netip.MustParseAddr("192.0.2.5")
				if err := m.Block(addr, "scan"); err != nil {
					t.Fatal(err)
				}
				m.mu.Lock()
				if err := m.unblockLocked(addr); err != nil {
					m.reportLocked(err)
				}
				m.mu.Unlock()
			},
		},
		{
			name: "the connection tables could not be read in full",
			run: func(report func(error)) {
				h := &SystemHostInfo{localAddrs: map[netip.Addr]bool{}}
				h.SetOnError(report)
				h.reportError(degraded("the connection tables could not be read in full: %w",
					errors.New("permission denied")))
			},
		},
		{
			name: "the eBPF path is unavailable and the fallback is in use",
			run: func(report func(error)) {
				_, _, err := selectSource(SourceAuto,
					func() (PacketSource, error) { return nil, fmt.Errorf("%w: no module", ErrEbpfUnavailable) },
					func() (PacketSource, error) { return newFakeSource(), nil },
					report)
				if err != nil {
					t.Fatalf("selectSource: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := collect(tc.run)
			if len(errs) == 0 {
				t.Fatal("the path reported nothing at all; this case is not exercising itself")
			}
			for _, e := range errs {
				if !IsDegradation(e) {
					t.Errorf("not marked as a degradation, so the daemon keeps it in the"+
						" log and the user never learns of it:\n  %v", e)
				}
			}
		})
	}
}

// TestDegradedWrapsRatherThanFlattens pins that marking an error keeps the one
// it wrapped reachable, so callers can still match on the underlying cause.
func TestDegradedWrapsRatherThanFlattens(t *testing.T) {
	inner := errors.New("ENOBUFS")
	e := degraded("reading the host addresses: %w", inner)
	if !IsDegradation(e) {
		t.Fatal("degraded() produced an error that is not a degradation")
	}
	if !errors.Is(e, inner) {
		t.Fatal("the wrapped cause is no longer reachable")
	}
	if !strings.Contains(e.Error(), "ENOBUFS") {
		t.Fatalf("the message lost its cause: %v", e)
	}
}

// statsSource is a packet source whose kernel counters the test sets.
type statsSource struct {
	fakeSource
	stats map[string]uint64
}

func (s *statsSource) Stats() (map[string]uint64, error) {
	out := map[string]uint64{}
	for k, v := range s.stats {
		out[k] = v
	}
	return out, nil
}

// TestOnePeerOverItsOwnBudgetIsNotDegradedDetection: the kernel counted a
// source refused by its own budget and one refused by the aggregate budget
// together, and every rise was reported as detection degraded for every
// source. One peer's download goes past its own budget, so every large
// download raised that warning once a minute, while no other source lost
// anything. Only the aggregate budget is reported.
func TestOnePeerOverItsOwnBudgetIsNotDegradedDetection(t *testing.T) {
	src := &statsSource{stats: map[string]uint64{"rate_limited": 0, "source_rate_limited": 0}}
	var errs []error
	m := &Monitor{source: src, onError: func(err error) { errs = append(errs, err) }}
	m.checkSourceDegradation()
	src.stats["source_rate_limited"] = 44640
	m.checkSourceDegradation()
	if len(errs) != 0 {
		t.Fatalf("one source over its own budget was reported: %v", errs)
	}
	src.stats["rate_limited"] = 10
	m.checkSourceDegradation()
	if len(errs) != 1 || !IsDegradation(errs[0]) {
		t.Fatalf("the aggregate budget refusing probes gave %v, want one degradation", errs)
	}
}

// TestAFPacketLossesAreReported: if the AF_PACKET source counted what its
// budget and the kernel's receive buffer dropped under names the monitor did
// not read, a fallback losing most of a scan would say nothing. It uses the
// kernel program's name for the aggregate budget, and its receive-buffer
// losses are read as well.
func TestAFPacketLossesAreReported(t *testing.T) {
	for _, key := range []string{"rate_limited", "kernel_dropped"} {
		af := newBudgetedAFPacketSource(10)
		src := &statsSource{stats: af.budgetStats()}
		src.stats["kernel_dropped"] = 0
		var errs []error
		m := &Monitor{source: src, onError: func(err error) { errs = append(errs, err) }}
		m.checkSourceDegradation()
		if key == "rate_limited" {
			for i := 0; i < 100; i++ {
				af.admit(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 0)
			}
			for k, v := range af.budgetStats() {
				src.stats[k] = v
			}
		} else {
			src.stats[key] = 7
		}
		m.checkSourceDegradation()
		if len(errs) != 1 || !IsDegradation(errs[0]) {
			t.Errorf("%s rising gave %v, want one degradation", key, errs)
		}
	}
}

// TestADegradationIsSaidOnceAnHourWhileItLasts: the source's loss counters are
// read once a minute, and every minute they rose gave a warning. Ordinary
// traffic can keep the aggregate budget spent -- a machine serving or seeding
// to twenty peers does -- and the user got sixty warnings an hour for one
// condition, then learned to ignore them. Each counter is said at most once an
// hour, whether its losses are continuous or come and go: restarting the hour
// after one quiet minute gave thirty warnings an hour to losses every other
// minute.
func TestADegradationIsSaidOnceAnHourWhileItLasts(t *testing.T) {
	src := &statsSource{stats: map[string]uint64{"rate_limited": 0}}
	var errs []error
	now := time.Now()
	m := &Monitor{source: src, onError: func(err error) { errs = append(errs, err) },
		now: func() time.Time { return now }}
	minute := func(rise uint64) {
		now = now.Add(time.Minute)
		src.stats["rate_limited"] += rise
		m.checkSourceDegradation()
	}
	minute(0)
	for i := 0; i < 59; i++ {
		minute(1000)
	}
	if len(errs) != 1 {
		t.Fatalf("59 minutes of losses gave %d warnings, want 1", len(errs))
	}
	minute(1000)
	minute(1000)
	if len(errs) != 2 {
		t.Fatalf("losses lasting past the hour gave %d warnings in all, want 2", len(errs))
	}
	for i := 0; i < 58; i++ {
		minute(uint64(i%2) * 1000)
	}
	if len(errs) != 2 {
		t.Fatalf("losses every other minute gave %d warnings in all within the hour, want 2", len(errs))
	}
	for i := 0; i < 90; i++ {
		minute(0)
	}
	minute(1000)
	if len(errs) != 3 {
		t.Fatalf("losses coming back after a quiet hour gave %d warnings in all, want 3", len(errs))
	}
}

// failingStatsSource reads its counters but reports that some of them could
// not be read, as the AF_PACKET source does when one socket fails.
type failingStatsSource struct{ statsSource }

func (s *failingStatsSource) Stats() (map[string]uint64, error) {
	out, _ := s.statsSource.Stats()
	return out, errors.New("one socket could not be read")
}

// TestAFailedCounterReadIsNotASilentCheck: a source that could read only
// some of its counters returned an error, and the whole check was skipped:
// ten minutes of aggregate-budget losses gave no warning. The counters it did
// read are still checked, and the failure is said, once an hour.
func TestAFailedCounterReadIsNotASilentCheck(t *testing.T) {
	src := &failingStatsSource{statsSource{stats: map[string]uint64{"rate_limited": 0}}}
	var errs []error
	now := time.Now()
	m := &Monitor{source: src, onError: func(err error) { errs = append(errs, err) },
		now: func() time.Time { return now }}
	for i := 0; i < 10; i++ {
		now = now.Add(time.Minute)
		src.stats["rate_limited"] += 5000
		m.checkSourceDegradation()
	}
	var losses, failures int
	for _, err := range errs {
		if !IsDegradation(err) {
			t.Errorf("not marked as a degradation: %v", err)
		}
		if strings.Contains(err.Error(), "rate_limited") {
			losses++
		} else {
			failures++
		}
	}
	if losses != 1 || failures != 1 {
		t.Fatalf("ten minutes of losses with a failing counter read gave %d loss and %d failure"+
			" warnings, want 1 and 1: %v", losses, failures, errs)
	}
}

// TestMaintenanceWarningsAreSaidOnceAnHour: the other conditions maintenance
// checks every minute -- a flood of addresses, dropped events, a host with no
// address -- were said every minute they held. A flood of forged
// source addresses -- which anyone can send -- then gave a warning a minute
// for as long as it lasted, the noise the loss counters were already spared.
func TestMaintenanceWarningsAreSaidOnceAnHour(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSources = 64
	e := newTestEngine(t, cfg, newFakeHost())
	var errs []error
	now := time.Now()
	m := &Monitor{cfg: cfg, engine: e, host: &SystemHostInfo{},
		onError: func(err error) { errs = append(errs, err) },
		now:     func() time.Time { return now }}
	at := sec
	for minute := 0; minute < 30; minute++ {
		now = now.Add(time.Minute)
		// A flood of forged addresses, three times the table.
		for i := 0; i < 3*64; i++ {
			at += ms
			e.Process(synProbe(at, netip.AddrFrom4([4]byte{10, byte(minute), byte(i >> 8), byte(i)}), victim, 22))
		}
		m.checkEvictionPressure()
		m.eventsDropped.Add(1)
		m.checkDroppedEvents()
		m.checkHostView()
	}
	var eviction, dropped, blind int
	for _, err := range errs {
		switch {
		case strings.Contains(err.Error(), "displaced"):
			eviction++
		case strings.Contains(err.Error(), "not acted on"):
			dropped++
		case strings.Contains(err.Error(), "no local addresses"):
			blind++
		}
	}
	if eviction != 1 || dropped != 1 || blind != 1 {
		t.Fatalf("30 minutes of a forged-source flood, of dropped events and of no address"+
			" gave %d, %d and %d warnings, want 1 of each", eviction, dropped, blind)
	}
}

// TestAWorseningLossIsSaidWithinTheHour: once a counter has been said, the
// next hour's losses were silent however much they grew: a torrent refused
// three hundred probes a minute, a flood then refused a thousand times more,
// and the only warning in the hour still read "+300". A minute losing at
// least ten times what was last said is said again.
func TestAWorseningLossIsSaidWithinTheHour(t *testing.T) {
	src := &statsSource{stats: map[string]uint64{"rate_limited": 0}}
	var errs []error
	now := time.Now()
	m := &Monitor{source: src, onError: func(err error) { errs = append(errs, err) },
		now: func() time.Time { return now }}
	minute := func(rise uint64) {
		now = now.Add(time.Minute)
		src.stats["rate_limited"] += rise
		m.checkSourceDegradation()
	}
	minute(0)
	for i := 0; i < 20; i++ {
		minute(300)
	}
	for i := 0; i < 10; i++ {
		minute(2000)
	}
	if len(errs) != 1 {
		t.Fatalf("losses growing less than tenfold gave %d warnings, want 1", len(errs))
	}
	minute(240000)
	minute(240000)
	if len(errs) != 2 || !strings.Contains(errs[1].Error(), "+240000") {
		t.Fatalf("a thousandfold worse minute gave %v, want a second warning saying +240000", errs)
	}
}

// TestACounterThatStartsOverIsNotALoss: a source that restarts starts its
// counters from zero, and the difference with the last reading wraps to an
// enormous number. That is not a loss.
func TestACounterThatStartsOverIsNotALoss(t *testing.T) {
	src := &statsSource{stats: map[string]uint64{"rate_limited": 1000}}
	var errs []error
	now := time.Now()
	m := &Monitor{source: src, onError: func(err error) { errs = append(errs, err) },
		now: func() time.Time { return now }}
	m.checkSourceDegradation()
	now = now.Add(2 * time.Hour)
	src.stats["rate_limited"] = 5
	m.checkSourceDegradation()
	if len(errs) != 0 {
		t.Fatalf("a counter starting over was reported as a loss: %v", errs)
	}
}

// TestEveryCounterThatRisesIsSaid: two counters rising in the same minute
// are two warnings, not the first one.
func TestEveryCounterThatRisesIsSaid(t *testing.T) {
	src := &statsSource{stats: map[string]uint64{"rate_limited": 0, "ringbuf_full": 0}}
	var errs []error
	m := &Monitor{source: src, onError: func(err error) { errs = append(errs, err) }}
	m.checkSourceDegradation()
	src.stats["rate_limited"] = 10
	src.stats["ringbuf_full"] = 10
	m.checkSourceDegradation()
	if len(errs) != 2 {
		t.Fatalf("two counters rising gave %d warnings, want 2: %v", len(errs), errs)
	}
}

// keyedStatsSource returns only the keys it is told to, or nothing, with an
// error when anything is missing, as a source that could read part of its
// counters does.
type keyedStatsSource struct {
	fakeSource
	stats map[string]uint64
	only  []string
	none  bool
}

func (s *keyedStatsSource) Stats() (map[string]uint64, error) {
	if s.none {
		return nil, errors.New("nothing could be read")
	}
	out := map[string]uint64{}
	for k, v := range s.stats {
		out[k] = v
	}
	if s.only == nil {
		return out, nil
	}
	part := map[string]uint64{}
	for _, k := range s.only {
		part[k] = out[k]
	}
	return part, errors.New("some counters could not be read")
}

// TestAPartialReadIsNotALossLater: a counter missing from one reading must not
// be compared with zero at the next, or its whole total would be reported as
// the last minute's loss. Nor may a reading that returned nothing drop the
// previous one, or the next minute's losses would go uncounted.
func TestAPartialReadIsNotALossLater(t *testing.T) {
	src := &keyedStatsSource{stats: map[string]uint64{"rate_limited": 1000000, "ringbuf_full": 0}}
	var losses []error
	m := &Monitor{source: src, onError: func(err error) {
		if strings.Contains(err.Error(), "rate_limited") {
			losses = append(losses, err)
		}
	}}
	m.checkSourceDegradation()
	src.only = []string{"ringbuf_full"}
	m.checkSourceDegradation()
	src.only = nil
	src.stats["rate_limited"] += 500
	m.checkSourceDegradation()
	if len(losses) != 1 || !strings.Contains(losses[0].Error(), "+500") {
		t.Fatalf("500 refusals after a reading that missed the counter gave %v, want one +500", losses)
	}
	src.none = true
	m.checkSourceDegradation()
	src.none = false
	now := time.Now().Add(2 * time.Hour)
	m.now = func() time.Time { return now }
	src.stats["rate_limited"] += 700
	m.checkSourceDegradation()
	if len(losses) != 2 || !strings.Contains(losses[1].Error(), "+700") {
		t.Fatalf("700 refusals after a reading that returned nothing gave %v, want a second, +700", losses)
	}
}

// TestEveryPacedWarningSaysItIsPaced: a warning said once an hour must say
// so, or its silence afterwards reads as the condition having ended.
func TestEveryPacedWarningSaysItIsPaced(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSources = 64
	e := newTestEngine(t, cfg, newFakeHost())
	src := &statsSource{stats: map[string]uint64{"rate_limited": 0}}
	var errs []error
	m := &Monitor{cfg: cfg, engine: e, source: src, host: &SystemHostInfo{},
		onError: func(err error) { errs = append(errs, err) }}
	m.checkSourceDegradation()
	src.stats["rate_limited"] = 10
	m.checkSourceDegradation()
	for i := 0; i < 3*64; i++ {
		e.Process(synProbe(sec+uint64(i)*ms, netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), victim, 22))
	}
	m.checkEvictionPressure()
	m.eventsDropped.Add(1)
	m.checkDroppedEvents()
	m.checkHostView()
	if len(errs) != 4 {
		t.Fatalf("got %d warnings, want 4: %v", len(errs), errs)
	}
	for _, err := range errs {
		if !strings.Contains(err.Error(), "once an hour") {
			t.Errorf("does not say it is paced: %v", err)
		}
	}
}

// pacingMonitor is a Monitor on a clock the test moves, whose warnings are
// counted by kind.
func pacingMonitor(t *testing.T) (*Monitor, *Engine, *statsSource, *time.Time, map[string]int) {
	cfg := testConfig()
	cfg.MaxSources = 64
	e := newTestEngine(t, cfg, newFakeHost())
	src := &statsSource{stats: map[string]uint64{"rate_limited": 0}}
	now := time.Now()
	said := map[string]int{}
	m := &Monitor{cfg: cfg, engine: e, source: src, host: &SystemHostInfo{},
		now: func() time.Time { return now },
		onError: func(err error) {
			for _, k := range []string{"rate_limited", "not acted on", "displaced", "no local addresses", "loss counters"} {
				if strings.Contains(err.Error(), k) {
					said[k]++
				}
			}
		}}
	return m, e, src, &now, said
}

// TestAQuietMinuteDoesNotUseTheHour: only a warning actually given starts its
// hour. Asked first, the pacing rule recorded a mark for every check, even
// one with nothing to say, and the first real warning after it was silent.
func TestAQuietMinuteDoesNotUseTheHour(t *testing.T) {
	m, e, src, now, said := pacingMonitor(t)
	m.host.localAddrs = map[netip.Addr]bool{victim: true}
	m.checkSourceDegradation()
	*now = now.Add(time.Minute)
	m.checkSourceDegradation()
	m.checkDroppedEvents()
	// Some churn, below the warning: a quiet minute is not an empty one.
	for i := 0; i < 2*64; i++ {
		e.Process(synProbe(sec+uint64(i)*ms, netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), victim, 22))
	}
	m.checkEvictionPressure()
	m.checkHostView()

	*now = now.Add(time.Minute)
	src.stats["rate_limited"] = 3
	m.checkSourceDegradation()
	m.eventsDropped.Add(3)
	m.checkDroppedEvents()
	for i := 0; i < 3*64; i++ {
		e.Process(synProbe(sec+uint64(i)*ms, netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}), victim, 22))
	}
	m.checkEvictionPressure()
	m.host.localAddrs = nil
	m.checkHostView()
	for _, k := range []string{"rate_limited", "not acted on", "displaced", "no local addresses"} {
		if said[k] != 1 {
			t.Errorf("%q after a quiet minute: %d warnings, want 1", k, said[k])
		}
	}
}

// TestEachWarningKindHasItsOwnHour: one kind of warning said must not
// silence another in the same hour.
func TestEachWarningKindHasItsOwnHour(t *testing.T) {
	m, _, src, now, said := pacingMonitor(t)
	m.checkSourceDegradation()
	m.checkHostView()
	*now = now.Add(time.Minute)
	m.source = &failingStatsSource{statsSource{stats: map[string]uint64{"rate_limited": 5}}}
	m.checkSourceDegradation()
	_ = src
	if said["no local addresses"] != 1 || said["loss counters"] != 1 || said["rate_limited"] != 1 {
		t.Fatalf("three kinds in one hour gave %v, want one of each", said)
	}
}

// TestEveryWarningKindIsSaidAgainWhenItGrowsTenfold: the tenfold rule holds
// for every kind, measured in its own size, and at exactly ten times.
func TestEveryWarningKindIsSaidAgainWhenItGrowsTenfold(t *testing.T) {
	m, e, src, now, said := pacingMonitor(t)
	m.checkSourceDegradation()
	flood := func(n, round int) {
		for i := 0; i < n; i++ {
			e.Process(synProbe(sec+uint64(round)*uint64(time.Hour)+uint64(i)*ms,
				netip.AddrFrom4([4]byte{10, byte(round), byte(i >> 8), byte(i)}), victim, 22))
		}
		m.checkEvictionPressure()
	}
	*now = now.Add(time.Minute)
	src.stats["rate_limited"] += 100
	m.checkSourceDegradation()
	m.eventsDropped.Add(2)
	m.checkDroppedEvents()
	flood(3*64, 1)
	*now = now.Add(time.Minute)
	src.stats["rate_limited"] += 1000
	m.checkSourceDegradation()
	m.eventsDropped.Add(20)
	m.checkDroppedEvents()
	flood(40*64, 2)
	for _, k := range []string{"rate_limited", "not acted on", "displaced"} {
		if said[k] != 2 {
			t.Errorf("%q growing tenfold within the hour: %d warnings, want 2", k, said[k])
		}
	}
}
