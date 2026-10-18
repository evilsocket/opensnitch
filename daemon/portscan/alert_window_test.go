package portscan

import (
	"math/rand"
	"testing"
	"time"
)

// TestAlertLimiterSurvivesBackwardsTimestamps pins that out-of-order probe
// timestamps cannot buy extra alerts.
//
// Both packet paths deliver probes whose timestamps step backwards, without
// anyone doing anything unusual: AF_PACKET stamps inside a per-interface
// goroutine, and the kernel program reads the clock before reserving its ring
// buffer slot. Treating a backwards step as a new window would reopen a full
// AlertsPerMinute budget each time. Measured without it, with the cap at 3:
// 19 alerts out of 20 for a strictly decreasing sequence, and EventsSuppressed
// left at 0 so nothing would record the overrun.
func TestAlertLimiterSurvivesBackwardsTimestamps(t *testing.T) {
	// An hour of uptime, so the first alert does not itself roll the window.
	const base = uint64(3600) * sec

	for _, step := range []struct {
		name string
		ns   uint64
	}{
		{"1ns", 1},
		{"1us", uint64(time.Microsecond)},
		{"1ms", uint64(time.Millisecond)},
	} {
		t.Run("decreasing by "+step.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.AlertsPerMinute = 3
			cfg.ReportCooldown = time.Hour
			e := newTestEngine(t, cfg, newFakeHost())

			const n = 20
			alerts := 0
			for i := 0; i < n; i++ {
				// Strictly decreasing, all inside one window.
				at := base + uint64(n)*step.ns - uint64(i)*step.ns
				if ev := crossOnce(e, srcN(i), at, uint16(1+10*i)); ev != nil {
					alerts++
				}
			}
			if alerts > cfg.AlertsPerMinute {
				t.Fatalf("%d alerts emitted inside one window, cap is %d",
					alerts, cfg.AlertsPerMinute)
			}
			if st := e.Stats(); st.EventsSuppressed == 0 {
				t.Fatal("sources were refused but EventsSuppressed stayed at 0")
			}
		})
	}
}

// TestAlertLimiterSurvivesReorderedDelivery is the same property under what
// out-of-order delivery actually looks like: a random permutation of crossing
// timestamps inside a narrow jitter band. Measured without the guard: 13.4
// alerts on average against a cap of 3.
func TestAlertLimiterSurvivesReorderedDelivery(t *testing.T) {
	const base = uint64(3600) * sec
	const jitter = uint64(time.Millisecond)
	const sources = 100

	worst := 0
	for seed := 0; seed < 20; seed++ {
		rng := rand.New(rand.NewSource(int64(seed)))
		cfg := testConfig()
		cfg.AlertsPerMinute = 3
		cfg.ReportCooldown = time.Hour
		e := newTestEngine(t, cfg, newFakeHost())

		order := rng.Perm(sources)
		alerts := 0
		for i, k := range order {
			at := base + uint64(k)*(jitter/sources)
			if ev := crossOnce(e, srcN(i), at, uint16(1+10*(i%200))); ev != nil {
				alerts++
			}
		}
		if alerts > worst {
			worst = alerts
		}
		if alerts > cfg.AlertsPerMinute {
			t.Fatalf("seed %d: %d alerts inside a 1 ms band, cap is %d",
				seed, alerts, cfg.AlertsPerMinute)
		}
	}
	t.Logf("worst case over 20 permutations: %d alerts, cap 3", worst)
}

// TestWindowRolledIsAsymmetric pins the shape of the guard itself, including
// the case that must still roll: a window start left far in the future would
// otherwise silence alerting for ever.
func TestWindowRolledIsAsymmetric(t *testing.T) {
	const w = uint64(time.Minute)
	cases := []struct {
		name       string
		start, now uint64
		rolled     bool
	}{
		{"same instant", 1000, 1000, false},
		{"one nanosecond back", 1000, 999, false},
		{"reordered by a millisecond", w, w - uint64(time.Millisecond), false},
		{"forward, inside the window", 1000, 1000 + w - 1, false},
		{"forward, exactly a window", 1000, 1000 + w, true},
		{"far behind: a clock anomaly, not reordering", 10 * w, 10*w - w, true},
	}
	for _, tc := range cases {
		if got := windowRolled(tc.start, tc.now, w); got != tc.rolled {
			t.Errorf("%s: windowRolled(%d, %d, %d) = %v, want %v",
				tc.name, tc.start, tc.now, w, got, tc.rolled)
		}
	}
}
