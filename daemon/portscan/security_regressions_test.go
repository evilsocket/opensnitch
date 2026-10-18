//go:build linux

package portscan

import (
	"net/netip"
	"testing"
	"time"
)

// TestOneStrayPacketDoesNotHideTheTechnique pins that a single probe of another
// family cannot turn a named technique into "mixed".
//
// describeMethod counted families first and let families > 1 outrank everything,
// so one extra datagram was enough to change "TCP SYN scan" into "several scan
// techniques combined": the cheapest possible way for a scanner to tell the
// victim less about what it did.
func TestOneStrayPacketDoesNotHideTheTechnique(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")

	cases := []struct {
		name  string
		stray func(*Engine, uint64)
	}{
		{"one UDP datagram", func(e *Engine, at uint64) {
			e.Process(udpProbe(at, attacker, local, 9999))
		}},
		{"one ICMP timestamp request", func(e *Engine, at uint64) {
			e.Process(icmpProbe(at, attacker, local, icmpv4Timestamp))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, testConfig(), newFakeHost())
			tc.stray(e, sec)
			var ev *ScanEvent
			for k := 0; k < 11; k++ {
				if got := e.Process(synProbe(sec+uint64(k+1)*ms, attacker, local, uint16(21+k))); got != nil && ev == nil {
					ev = got
				}
			}
			if ev == nil {
				t.Fatal("the SYN scan was not reported at all")
			}
			if ev.Method != MethodSYN {
				t.Fatalf("method = %v, want tcp-syn: one stray packet erased the technique",
					ev.Method)
			}
		})
	}

	// A genuinely mixed scan is still called mixed: both families send many.
	e := newTestEngine(t, testConfig(), newFakeHost())
	for k := 0; k < 6; k++ {
		e.Process(synProbe(sec+uint64(k)*ms, attacker, local, uint16(21+k)))
		e.Process(udpProbe(sec+uint64(k)*ms+1, attacker, local, uint16(50+k)))
	}
	var ev *ScanEvent
	for k := 6; k < 14; k++ {
		if got := e.Process(synProbe(sec+uint64(k)*ms, attacker, local, uint16(21+k))); got != nil && ev == nil {
			ev = got
		}
	}
	if ev != nil && ev.Method != MethodMixed {
		t.Fatalf("a scan using both TCP and UDP heavily reported %v, want mixed", ev.Method)
	}
}

// TestOverCapEntryIsNotRefreshed pins that the entry recorded because the
// backend refused to take it out keeps its place at the front of the queue for
// removal.
//
// It is deliberately stored expired and at the back of the list, so it leaves at
// the first opportunity: it is the address that should not be in the firewall at
// all. The "already blocked" branch extended every entry and moved it to the
// front, so a later Block on that address gave it a full duration and made it
// the most recently used -- and the firewall stayed over MaxBlockedSources for
// that much longer.
func TestOverCapEntryIsNotRefreshed(t *testing.T) {
	b := &failingUnblocker{fakeBlocker: newFakeBlocker(), fail: false}
	const maxBlocks = 2
	m, err := NewBlockManager(b, BlockConfig{Duration: time.Hour, MaxBlockedSources: maxBlocks},
		func(netip.Addr) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	m.SetOnError(func(error) {})

	for i := 0; i < maxBlocks; i++ {
		if err := m.Block(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), "scan"); err != nil {
			t.Fatal(err)
		}
	}
	over := netip.MustParseAddr("198.51.100.200")
	b.fail = true
	_ = m.Block(over, "scan")
	b.fail = false

	var before time.Time
	for _, e := range m.Blocked() {
		if e.Addr == over {
			before = e.ExpiresAt
		}
	}
	if before.IsZero() {
		t.Skip("the over-cap entry was not recorded; nothing to check")
	}

	// A second detection of the same source must not renew it.
	_ = m.Block(over, "scan again")

	for _, e := range m.Blocked() {
		if e.Addr == over && e.ExpiresAt.After(before) {
			t.Fatalf("the over-cap entry was renewed: expiry moved from %v to %v,"+
				" so the firewall stays above the cap for a full block duration",
				before, e.ExpiresAt)
		}
	}
}

// TestDangerousSettingsAreReported pins that a configuration which switches
// detection off in practice says so.
//
// Validate draws its limits where the arithmetic overflows, and several of its
// own error messages describe a danger and then accept the value that realises
// it: StartupGrace may be 24 hours, which on a machine rebooted daily is the off
// switch its neighbouring message warns about.
func TestDangerousSettingsAreReported(t *testing.T) {
	cases := []struct {
		name string
		tune func(*Config)
	}{
		{"a day of startup grace", func(c *Config) { c.StartupGrace = 24 * time.Hour }},
		{"a bucket that never leaks", func(c *Config) { c.DecayInterval = 24 * time.Hour }},
		{"a threshold beyond any scan", func(c *Config) { c.ScoreThreshold = 1 << 20 }},
		{"no cap on notifications", func(c *Config) { c.AlertsPerMinute = 600 }},
		{"auto blocking on forgeable evidence", func(c *Config) {
			c.Block.Policy = BlockAuto
			c.Block.RequireTCPEvidence = false
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Enabled = true
			tc.tune(&cfg)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("the configuration is refused outright (%v); this test is about"+
					" values that are ACCEPTED", err)
			}
			if w := cfg.Warnings(); len(w) == 0 {
				t.Fatal("accepted silently: the user is not told that detection is" +
					" effectively off")
			}
		})
	}

	// And the shipped defaults say nothing, or the warning would be noise.
	d := DefaultConfig()
	d.Enabled = true
	if w := d.Warnings(); len(w) != 0 {
		t.Fatalf("the default configuration warns about %v", w)
	}
}
