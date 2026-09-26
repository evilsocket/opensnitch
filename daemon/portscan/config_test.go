//go:build linux

package portscan

import (
	"testing"
	"time"
)

// TestValidateBoundsTheDurations: Validate had no upper bound on DecayInterval,
// IdleExpiry or StartupGrace, and the arithmetic built on them overflows well
// before the values stop being meaningful.
//
// SlowestDetectableScan multiplies DecayInterval by a probe weight, so past
// MaxInt64/16 -- about eighteen years -- the product went negative and the
// function reported "no scan of that weight can ever be detected". The truth is
// the exact opposite: with a decay interval that long the bucket never leaks and
// EVERY source eventually crosses the threshold. The coverage report and the
// documentation are generated from that function.
//
// StartupGrace had the same gap: ten years passed validation and switched
// detection off on both paths while the daemon logged itself as active.
func TestValidateBoundsTheDurations(t *testing.T) {
	for _, tc := range []struct {
		name string
		tune func(*Config)
	}{
		{"DecayInterval of 292 years", func(c *Config) { c.DecayInterval = 292 * 365 * 24 * time.Hour }},
		{"StartupGrace of ten years", func(c *Config) { c.StartupGrace = 10 * 365 * 24 * time.Hour }},
		{"IdleExpiry of a century", func(c *Config) { c.IdleExpiry = 100 * 365 * 24 * time.Hour }},
		{"ProtoScanMinProtocols past the protocol space", func(c *Config) { c.ProtoScanMinProtocols = 257 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			tc.tune(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("Validate accepted %s", tc.name)
			}
		})
	}

	// And the defaults, plus the extremes that remain legal, still validate.
	c := DefaultConfig()
	c.DecayInterval = maxDecayInterval
	c.StartupGrace = maxStartupGrace
	c.IdleExpiry = maxIdleExpiry
	c.ProtoScanMinProtocols = 256
	if err := c.Validate(); err != nil {
		t.Fatalf("the largest legal values were rejected: %v", err)
	}
	if d := c.SlowestDetectableScan(12); d <= 0 {
		t.Errorf("SlowestDetectableScan = %v at the bound, want a positive duration", d)
	}
}

// TestValidateRejectsEveryUpperBoundByOne: each upper bound refuses one past
// it and accepts itself. Three of them had no test at all, and Block.Duration
// past 30 days is where the uint32 of seconds the UI shows wraps around: the
// GUI would say minutes while the daemon installs a century.
func TestValidateRejectsEveryUpperBoundByOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		tune func(*Config)
	}{
		{"MaxBlockedSources", func(c *Config) { c.Block.MaxBlockedSources = maxBlockedSourcesLimit + 1 }},
		{"Block.Duration", func(c *Config) { c.Block.Duration = maxBlockDuration + time.Second }},
		{"AlertsPerMinute", func(c *Config) { c.AlertsPerMinute = maxAlertsPerMinute + 1 }},
		{"ScoreThreshold", func(c *Config) { c.ScoreThreshold = 1<<20 + 1 }},
	} {
		c := DefaultConfig()
		tc.tune(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("Validate accepted %s one past its bound", tc.name)
		}
	}
	c := DefaultConfig()
	c.Block.MaxBlockedSources = maxBlockedSourcesLimit
	c.Block.Duration = maxBlockDuration
	c.AlertsPerMinute = maxAlertsPerMinute
	c.ScoreThreshold = 1 << 20
	if err := c.Validate(); err != nil {
		t.Errorf("the bounds themselves were rejected: %v", err)
	}
}
