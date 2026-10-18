package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/portscan"
)

func TestDefaultPortScanOptionsRoundTrip(t *testing.T) {
	opts := DefaultPortScanOptions()
	cfg, lists, err := opts.ToPortScanConfig()
	if err != nil {
		t.Fatalf("the shipped defaults do not convert: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the shipped defaults are not valid: %v", err)
	}
	if len(lists.NeverBlock) != 0 {
		t.Errorf("default NeverBlock = %v, want empty (the mandatory entries are added below this layer)", lists.NeverBlock)
	}

	// The JSON form must agree with the detection package's own defaults, field
	// for field.
	//
	// Checking a few fields by name would miss the one that matters: a field
	// added to portscan.Config and never to PortScanOptions (DetectICMPSweep,
	// for instance) would be left at false by ToPortScanConfig -- which builds
	// a Config field by field -- on every real daemon whatever the file said.
	// The whole ICMP detector would be dead code in production while its own
	// tests passed, because those tests construct a Config directly and never
	// go through here.
	//
	// Comparing the whole struct is the only form of this check that cannot be
	// out of date: a new field that nobody wired shows up as a zero value.
	d := portscan.DefaultConfig()
	if !reflect.DeepEqual(cfg, d) {
		t.Errorf("the converted defaults differ from portscan.DefaultConfig():\n got %+v\nwant %+v", cfg, d)
	}
}

// TestEveryConfigFieldIsReachableFromJSON pins that no field of the detection
// package's configuration is unreachable from the configuration file.
//
// The round trip above catches a field whose default is non-zero. This catches
// the other half: a field whose default happens to BE the zero value would
// convert identically whether or not anyone had wired it.
func TestEveryConfigFieldIsReachableFromJSON(t *testing.T) {
	have := map[string]bool{}
	for _, tp := range []reflect.Type{
		reflect.TypeOf(PortScanOptions{}), reflect.TypeOf(PortScanBlockOptions{}),
	} {
		for i := 0; i < tp.NumField(); i++ {
			have[tp.Field(i).Name] = true
		}
	}
	for _, tp := range []reflect.Type{
		reflect.TypeOf(portscan.Config{}), reflect.TypeOf(portscan.BlockConfig{}),
	} {
		for i := 0; i < tp.NumField(); i++ {
			if n := tp.Field(i).Name; !have[n] {
				t.Errorf("portscan.%s.%s has no counterpart in the JSON options:"+
					" it can never be set from the configuration file", tp.Name(), n)
			}
		}
	}
}

// TestDefaultBlockPolicyIsAsk pins the shipped behaviour.
//
// The user asked for a 4h block on detection; the default is to ask first,
// because the source address of a scan is forgeable and nmap -D would
// otherwise let an attacker choose which of the victim's own infrastructure
// gets blocked. Changing this default is a deliberate act, not a drive-by edit.
func TestDefaultBlockPolicyIsAsk(t *testing.T) {
	d := DefaultPortScanOptions()
	if d.Block.Policy != string(portscan.BlockAsk) {
		t.Errorf("default Block.Policy = %q, want %q", d.Block.Policy, portscan.BlockAsk)
	}
	if d.Block.Duration != "4h0m0s" {
		t.Errorf("default Block.Duration = %q, want 4 hours", d.Block.Duration)
	}
	if !d.Block.RequireTCPEvidence {
		t.Error("RequireTCPEvidence is off by default; UDP-only evidence must not move a firewall")
	}
}

func TestPortScanOptionsParseFromJSON(t *testing.T) {
	raw := `{
      "Enabled": true,
      "Source": "afpacket",
      "ScoreThreshold": 60,
      "DecayInterval": "5s",
      "MaxSources": 1024,
      "IdleExpiry": "10m",
      "StartupGrace": "30s",
      "ProtoScanMinProtocols": 4,
      "AlertsPerMinute": 2,
      "ReportCooldown": "1m",
      "DetectTCP": true, "DetectUDP": true, "DetectProtocolScan": true,
      "ExcludedPorts": [67, 68, 5353],
      "Block": {
        "Policy": "auto",
        "Duration": "2h",
        "MaxBlockedSources": 16,
        "RequireTCPEvidence": true,
        "NeverBlock": ["192.0.2.0/24", "2001:db8::/32"]
      }
    }`
	var opts PortScanOptions
	if err := json.Unmarshal([]byte(raw), &opts); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	cfg, lists, err := opts.ToPortScanConfig()
	if err != nil {
		t.Fatalf("ToPortScanConfig: %v", err)
	}
	if cfg.DecayInterval != 5*time.Second {
		t.Errorf("DecayInterval = %v, want 5s", cfg.DecayInterval)
	}
	if cfg.Block.Duration != 2*time.Hour {
		t.Errorf("Block.Duration = %v, want 2h", cfg.Block.Duration)
	}
	if cfg.Block.Policy != portscan.BlockAuto {
		t.Errorf("Block.Policy = %q, want auto", cfg.Block.Policy)
	}
	if len(cfg.ExcludedPorts) != 3 {
		t.Errorf("ExcludedPorts = %v, want 3 entries", cfg.ExcludedPorts)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if len(lists.NeverBlock) != len(want) {
		t.Fatalf("NeverBlock = %v, want %v", lists.NeverBlock, want)
	}
	for i := range want {
		if lists.NeverBlock[i] != want[i] {
			t.Errorf("NeverBlock[%d] = %v, want %v", i, lists.NeverBlock[i], want[i])
		}
	}
}

// TestPortScanOptionsRejectBadValues checks that a malformed setting stops the
// feature rather than being silently replaced by a default.
func TestPortScanOptionsRejectBadValues(t *testing.T) {
	base := DefaultPortScanOptions()
	cases := []struct {
		name    string
		mutate  func(*PortScanOptions)
		wantSub string
	}{
		{"bad decay", func(o *PortScanOptions) { o.DecayInterval = "10 seconds" }, "DecayInterval"},
		{"bad block duration", func(o *PortScanOptions) { o.Block.Duration = "4 hours" }, "Block.Duration"},
		{"bad never-block prefix", func(o *PortScanOptions) { o.Block.NeverBlock = []string{"192.0.2.1"} }, "NeverBlock"},
		{"bad source", func(o *PortScanOptions) { o.Source = "magic" }, "Source"},
		{"bad port", func(o *PortScanOptions) { o.ExcludedPorts = &[]int{70000} }, "ExcludedPorts"},
		{"unknown policy", func(o *PortScanOptions) { o.Block.Policy = "maybe" }, "Policy"},
		{"zero threshold", func(o *PortScanOptions) { o.ScoreThreshold = 0 }, "ScoreThreshold"},
		// A never-count prefix covering everything switches detection off for
		// that family while the daemon reports it running.
		{"never-count everything v4", func(o *PortScanOptions) { o.NeverCount = []string{"0.0.0.0/0"} }, "NeverCount"},
		{"never-count everything v6", func(o *PortScanOptions) { o.NeverCount = []string{"::/0"} }, "NeverCount"},
		{"never-count host bits", func(o *PortScanOptions) { o.NeverCount = []string{"192.168.1.5/24"} }, "NeverCount"},
		// An IPv4-mapped prefix contains no IPv4 source, so it would protect
		// nothing while reading as protection. The message gives the IPv4 form.
		{"never-block mapped host", func(o *PortScanOptions) { o.Block.NeverBlock = []string{"::ffff:192.0.2.9/128"} }, `"192.0.2.9/32"`},
		{"never-block mapped network", func(o *PortScanOptions) { o.Block.NeverBlock = []string{"::ffff:203.0.113.0/120"} }, `"203.0.113.0/24"`},
		{"never-count mapped", func(o *PortScanOptions) { o.NeverCount = []string{"::ffff:198.51.100.0/120"} }, "NeverCount"},
		{"never-block mapped wide", func(o *PortScanOptions) { o.Block.NeverBlock = []string{"::ffff:0.0.0.0/90"} }, "NeverBlock"},
		// The suggestion is the IPv4 form, not another mapped prefix, even
		// when the host bits are set too.
		{"never-block mapped with host bits", func(o *PortScanOptions) { o.Block.NeverBlock = []string{"::ffff:192.0.2.5/120"} }, `"192.0.2.0/24" for the network or "192.0.2.5/32"`},
		{"never-count mapped everything", func(o *PortScanOptions) { o.NeverCount = []string{"::ffff:0:0/96"} }, "every IPv4 source"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.mutate(&o)
			_, _, err := o.ToPortScanConfig()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not name the offending field %q", err, tc.wantSub)
			}
		})
	}
}

// TestNeverBlockTypoIsFatal is worth its own test.
//
// An unparsable entry in the never-block list must stop the feature, not be
// skipped with a warning: the operator listed that address precisely so it
// could not be blocked, and carrying on without it would do the very thing
// they asked to prevent.
func TestNeverBlockTypoIsFatal(t *testing.T) {
	o := DefaultPortScanOptions()
	o.Block.NeverBlock = []string{"10.0.0.0/8", "192.168.1.0/33"}
	if _, _, err := o.ToPortScanConfig(); err == nil {
		t.Fatal("a malformed never-block prefix was ignored instead of refused")
	}
}

// TestAbsentPortScanKeyUsesDefaults: a configuration file written before this
// feature existed must keep working.
func TestAbsentPortScanKeyUsesDefaults(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"DefaultAction":"deny"}`), &c); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if c.PortScan != nil {
		t.Fatal("PortScan should be nil when the key is absent")
	}
	cfg, _, source, err := c.PortScanConfig()
	if err != nil {
		t.Fatalf("PortScanConfig: %v", err)
	}
	if source != PortScanSourceAuto {
		t.Errorf("source = %q, want %q", source, PortScanSourceAuto)
	}
	if cfg.ScoreThreshold != portscan.DefaultScoreThreshold {
		t.Errorf("ScoreThreshold = %d, want the default %d", cfg.ScoreThreshold, portscan.DefaultScoreThreshold)
	}
}

// TestFeatureIsOffUnlessAskedFor guards against switching the feature on for
// every existing OpenSnitch installation.
//
// The "Port Scan Detection" wiki page is titled "Turning it on" and tells the
// reader to add a PortScan block to their configuration. A configuration with
// no PortScan key falls back to DefaultPortScanOptions; if its Enabled came
// from portscan.DefaultConfig() and was true, the code would do the opposite.
// Since the package installs default-config.json as a conffile, an existing
// user's file has no PortScan key either -- so a package upgrade alone would
// start attaching a TC ingress program, or opening AF_PACKET sockets, on every
// machine, with a blocking policy already set, without anyone having asked.
func TestFeatureIsOffUnlessAskedFor(t *testing.T) {
	// A configuration that says nothing about port scanning.
	var cfg Config
	if err := json.Unmarshal([]byte(`{"DefaultAction":"allow"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	scanCfg, _, _, err := cfg.PortScanConfig()
	if err != nil {
		t.Fatalf("PortScanConfig on a configuration with no PortScan key: %v", err)
	}
	if scanCfg.Enabled {
		t.Error("a configuration that never mentions port scanning enables it")
	}

	// And saying so turns it on.
	if err := json.Unmarshal([]byte(`{"PortScan":{"Enabled":true}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	scanCfg, _, _, err = cfg.PortScanConfig()
	if err != nil {
		t.Fatalf("PortScanConfig with Enabled true: %v", err)
	}
	if !scanCfg.Enabled {
		t.Error(`"PortScan": {"Enabled": true} did not enable it`)
	}
}

// TestShippedConfigDoesNotEnableIt reads the file the package actually installs.
func TestShippedConfigDoesNotEnableIt(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "data", "default-config.json"))
	if err != nil {
		t.Skipf("the shipped configuration is not readable from here: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("the shipped default-config.json does not parse: %v", err)
	}
	scanCfg, _, _, err := cfg.PortScanConfig()
	if err != nil {
		t.Fatalf("the shipped default-config.json is not a valid port scan configuration: %v", err)
	}
	if scanCfg.Enabled {
		t.Error("the shipped default-config.json enables port scan detection")
	}
}

// TestEveryFieldReachesTheConfigWithANonDefaultValue sets every field of the
// JSON section to something other than its default and requires it to come out
// in portscan.Config. The round-trip test with the shipped defaults cannot see
// a field that is never copied: the default fills it in and the comparison
// passes. That is how DetectICMPSweep could stay false on every real daemon,
// and how ReportCooldown, Interfaces or an explicit empty ExcludedPorts could
// be dropped without a failing test.
//
// Two documents, because some booleans default to true and turning all four
// detectors off at once is refused.
func TestEveryFieldReachesTheConfigWithANonDefaultValue(t *testing.T) {
	common := `"Enabled": true, "Interfaces": ["eth9"],
	  "ScoreThreshold": 150, "DecayInterval": "7s", "MaxSources": 5000,
	  "IdleExpiry": "45m", "StartupGrace": "13s", "ICMPSweepMinTypes": 4,
	  "ProtoScanMinProtocols": 6, "AlertsPerMinute": 5, "ReportCooldown": "7m",
	  "ExcludedPorts": [], "NeverCount": ["198.51.100.0/24"],
	  "Block": {"Policy": "auto", "Duration": "2h", "MaxBlockedSources": 7,
	            "RequireTCPEvidence": false, "NeverBlock": ["192.0.2.0/24"]}`
	docs := []string{
		`{` + common + `, "DetectTCP": false, "DetectUDP": false}`,
		`{` + common + `, "DetectProtocolScan": false, "DetectICMPSweep": false}`,
	}

	d := portscan.DefaultConfig()
	differs := map[string]bool{}
	for i, doc := range docs {
		var o PortScanOptions
		if err := json.Unmarshal([]byte(doc), &o); err != nil {
			t.Fatal(err)
		}
		cfg, lists, err := o.ToPortScanConfig()
		if err != nil {
			t.Fatalf("document %d: %v", i, err)
		}
		want := portscan.Config{
			Enabled: true, Interfaces: []string{"eth9"},
			DetectTCP: i == 1, DetectUDP: i == 1, DetectProtocolScan: i == 0, DetectICMPSweep: i == 0,
			ScoreThreshold: 150, DecayInterval: 7 * time.Second, MaxSources: 5000,
			IdleExpiry: 45 * time.Minute, StartupGrace: 13 * time.Second, ICMPSweepMinTypes: 4,
			ProtoScanMinProtocols: 6, AlertsPerMinute: 5, ReportCooldown: 7 * time.Minute,
			ExcludedPorts: []uint16{},
			Block: portscan.BlockConfig{Policy: portscan.BlockAuto, Duration: 2 * time.Hour,
				MaxBlockedSources: 7, RequireTCPEvidence: false},
		}
		if !reflect.DeepEqual(cfg, want) {
			t.Errorf("document %d:\n got  %+v\n want %+v", i, cfg, want)
		}
		if len(lists.NeverCount) != 1 || lists.NeverCount[0] != netip.MustParsePrefix("198.51.100.0/24") {
			t.Errorf("NeverCount = %v", lists.NeverCount)
		}
		if len(lists.NeverBlock) != 1 || lists.NeverBlock[0] != netip.MustParsePrefix("192.0.2.0/24") {
			t.Errorf("NeverBlock = %v", lists.NeverBlock)
		}
		markDiffering(reflect.ValueOf(want), reflect.ValueOf(d), "", differs)
	}
	// The test itself must keep up: a field added to portscan.Config and not
	// given a non-default value above would pass on its default.
	var walk func(reflect.Type, string)
	walk = func(ty reflect.Type, prefix string) {
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeOf(time.Duration(0)) {
				walk(f.Type, prefix+f.Name+".")
				continue
			}
			if !differs[prefix+f.Name] {
				t.Errorf("%s%s is never set to a non-default value by this test", prefix, f.Name)
			}
		}
	}
	walk(reflect.TypeOf(portscan.Config{}), "")
}

func markDiffering(a, b reflect.Value, prefix string, out map[string]bool) {
	for i := 0; i < a.NumField(); i++ {
		name := prefix + a.Type().Field(i).Name
		fa, fb := a.Field(i), b.Field(i)
		if fa.Kind() == reflect.Struct {
			markDiffering(fa, fb, name+".", out)
			continue
		}
		if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
			out[name] = true
		}
	}
}
