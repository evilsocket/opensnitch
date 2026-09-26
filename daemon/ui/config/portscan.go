package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/evilsocket/opensnitch/daemon/portscan"
)

// Packet source selectors accepted in PortScanOptions.Source.
const (
	// PortScanSourceAuto tries eBPF and falls back to AF_PACKET.
	PortScanSourceAuto = "auto"
	// PortScanSourceEbpf requires eBPF and fails loudly if it is unavailable.
	PortScanSourceEbpf = "ebpf"
	// PortScanSourceAFPacket forces the AF_PACKET fallback.
	PortScanSourceAFPacket = "afpacket"
)

// DefaultPortScanOptions returns the shipped defaults in their JSON form,
// derived from the detection package's own defaults so the two can never drift.
func DefaultPortScanOptions() PortScanOptions {
	d := portscan.DefaultConfig()
	ports := make([]int, 0, len(d.ExcludedPorts))
	maxBlocked := d.Block.MaxBlockedSources
	for _, p := range d.ExcludedPorts {
		ports = append(ports, int(p))
	}
	return PortScanOptions{
		Enabled:               d.Enabled,
		Source:                PortScanSourceAuto,
		DetectTCP:             d.DetectTCP,
		DetectUDP:             d.DetectUDP,
		DetectProtocolScan:    d.DetectProtocolScan,
		DetectICMPSweep:       d.DetectICMPSweep,
		ScoreThreshold:        d.ScoreThreshold,
		DecayInterval:         d.DecayInterval.String(),
		MaxSources:            d.MaxSources,
		IdleExpiry:            d.IdleExpiry.String(),
		StartupGrace:          d.StartupGrace.String(),
		ProtoScanMinProtocols: d.ProtoScanMinProtocols,
		ICMPSweepMinTypes:     d.ICMPSweepMinTypes,
		AlertsPerMinute:       d.AlertsPerMinute,
		ReportCooldown:        d.ReportCooldown.String(),
		ExcludedPorts:         &ports,
		Block: PortScanBlockOptions{
			Policy:             string(d.Block.Policy),
			Duration:           d.Block.Duration.String(),
			MaxBlockedSources:  &maxBlocked,
			RequireTCPEvidence: d.Block.RequireTCPEvidence,
		},
	}
}

// parseDuration turns a configured string into a duration, naming the field in
// the error so an operator can find their typo.
//
// An empty string means "keep the default". A malformed one is an error, never
// a silent fallback: a threshold quietly replaced by a default is a threshold
// the operator believes is in force when it is not. This is the same hazard
// that made scanlogd's off-by-one reachable once its compile-time constants
// became runtime-configurable (scanlogd commit 66f425d).
func parseDuration(field, value string, dflt time.Duration) (time.Duration, error) {
	if value == "" {
		return dflt, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("PortScan.%s: %q is not a valid duration (try \"10s\", \"5m\", \"4h\"): %w", field, value, err)
	}
	return d, nil
}

// PortScanLists are the two prefix lists, which answer different questions and
// must not be conflated: NeverCount suppresses detection, NeverBlock only
// forbids a firewall rule.
type PortScanLists struct {
	NeverCount []netip.Prefix
	NeverBlock []netip.Prefix
}

// ToPortScanConfig converts the JSON form into the detection package's
// configuration, and returns the two prefix lists separately.
//
// It validates rather than clamps, so a nonsensical configuration stops the
// feature from starting instead of running with values the operator did not
// choose.
func (o *PortScanOptions) ToPortScanConfig() (portscan.Config, PortScanLists, error) {
	var lists PortScanLists
	d := portscan.DefaultConfig()
	cfg := portscan.Config{
		Enabled:               o.Enabled,
		Interfaces:            o.Interfaces,
		DetectTCP:             o.DetectTCP,
		DetectUDP:             o.DetectUDP,
		DetectProtocolScan:    o.DetectProtocolScan,
		DetectICMPSweep:       o.DetectICMPSweep,
		ScoreThreshold:        o.ScoreThreshold,
		MaxSources:            o.MaxSources,
		ProtoScanMinProtocols: o.ProtoScanMinProtocols,
		ICMPSweepMinTypes:     o.ICMPSweepMinTypes,
		AlertsPerMinute:       o.AlertsPerMinute,
	}

	var err error
	if cfg.DecayInterval, err = parseDuration("DecayInterval", o.DecayInterval, d.DecayInterval); err != nil {
		return cfg, lists, err
	}
	if cfg.IdleExpiry, err = parseDuration("IdleExpiry", o.IdleExpiry, d.IdleExpiry); err != nil {
		return cfg, lists, err
	}
	if cfg.StartupGrace, err = parseDuration("StartupGrace", o.StartupGrace, d.StartupGrace); err != nil {
		return cfg, lists, err
	}
	if cfg.ReportCooldown, err = parseDuration("ReportCooldown", o.ReportCooldown, d.ReportCooldown); err != nil {
		return cfg, lists, err
	}

	// A pointer, so that an explicitly empty list means "exclude nothing" and
	// an absent key means "use the defaults". With a plain slice the two would
	// be indistinguishable: the shipped list of ten ports would come back over
	// an operator who wrote [], leaving those ten never counted, and a scanner
	// confined to them invisible, while the operator believed they had turned
	// the exclusions off.
	if o.ExcludedPorts != nil {
		cfg.ExcludedPorts = make([]uint16, 0, len(*o.ExcludedPorts))
		for _, p := range *o.ExcludedPorts {
			if p < 0 || p > 65535 {
				return cfg, lists, fmt.Errorf("PortScan.ExcludedPorts: %d is not a valid port number", p)
			}
			cfg.ExcludedPorts = append(cfg.ExcludedPorts, uint16(p))
		}
	} else {
		cfg.ExcludedPorts = d.ExcludedPorts
	}

	cfg.Block = portscan.BlockConfig{
		RequireTCPEvidence: o.Block.RequireTCPEvidence,
	}
	if o.Block.MaxBlockedSources != nil {
		cfg.Block.MaxBlockedSources = *o.Block.MaxBlockedSources
	} else {
		cfg.Block.MaxBlockedSources = d.Block.MaxBlockedSources
	}
	cfg.Block.Policy = portscan.BlockPolicy(o.Block.Policy)
	if o.Block.Policy == "" {
		cfg.Block.Policy = d.Block.Policy
	}
	if cfg.Block.Duration, err = parseDuration("Block.Duration", o.Block.Duration, d.Block.Duration); err != nil {
		return cfg, lists, err
	}

	if lists.NeverBlock, err = parsePrefixes("Block.NeverBlock", o.Block.NeverBlock, false); err != nil {
		return cfg, lists, err
	}
	if lists.NeverCount, err = parsePrefixes("NeverCount", o.NeverCount, true); err != nil {
		return cfg, lists, err
	}

	switch o.Source {
	case "", PortScanSourceAuto, PortScanSourceEbpf, PortScanSourceAFPacket:
	default:
		return cfg, lists, fmt.Errorf("PortScan.Source: %q is not one of %q, %q, %q",
			o.Source, PortScanSourceAuto, PortScanSourceEbpf, PortScanSourceAFPacket)
	}

	if err := cfg.Validate(); err != nil {
		return cfg, lists, err
	}
	return cfg, lists, nil
}

// parsePrefixes converts and checks a CIDR list.
//
// refuseDefault rejects 0.0.0.0/0 and ::/0 for the never-count list, where they
// would switch detection off for a whole address family while the daemon went
// on logging that detection was active. They are legitimate in the never-block
// list, where they mean "alert me but never touch my firewall" -- a defensible
// choice, and one the operator can see they made.
func parsePrefixes(field string, in []string, refuseDefault bool) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// An unparsable entry must not be skipped with a warning: the
			// operator listed it precisely so that address would be treated
			// specially, and carrying on without it does the opposite.
			return nil, fmt.Errorf("PortScan.%s: %q is not a valid CIDR prefix: %w", field, s, err)
		}
		// Detection and blocking see an IPv4 source as IPv4, never in its
		// IPv4-mapped IPv6 form, and an IPv6 prefix never contains an IPv4
		// address: "::ffff:192.0.2.1/128" would be accepted and protect
		// nothing. Checked first, so the form suggested is the IPv4 one. A
		// shorter prefix than /96 has host bits set, and is refused below.
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			v4 := netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			if refuseDefault && v4.Bits() == 0 {
				return nil, fmt.Errorf("PortScan.%s: %q would disable detection for every IPv4 source, and as an IPv4-mapped prefix it matches none; remove it",
					field, s)
			}
			if v4 != v4.Masked() {
				return nil, fmt.Errorf("PortScan.%s: %q is an IPv4-mapped IPv6 prefix, which matches no IPv4 source; write %q for the network or %q for the single address",
					field, s, v4.Masked(), netip.PrefixFrom(v4.Addr(), 32))
			}
			return nil, fmt.Errorf("PortScan.%s: %q is an IPv4-mapped IPv6 prefix, which matches no IPv4 source; write %q",
				field, s, v4)
		}
		// A prefix with host bits set is masked away by Contains, so
		// "192.168.1.5/24" silently covers the whole /24 -- an operator writing
		// it almost certainly meant one host. Refusing is the only way they
		// find out.
		if p != p.Masked() {
			return nil, fmt.Errorf("PortScan.%s: %q has host bits set; write %q for the network or %q for the single address",
				field, s, p.Masked(), netip.PrefixFrom(p.Addr(), p.Addr().BitLen()))
		}
		if refuseDefault && p.Bits() == 0 {
			return nil, fmt.Errorf("PortScan.%s: %q would disable detection for the whole address family; remove it, or set Enabled to false if that is what you mean",
				field, s)
		}
		out = append(out, p)
	}
	return out, nil
}

// PortScanConfig returns the effective port scan configuration, falling back
// to the shipped defaults when the key is absent from the file.
func (c *Config) PortScanConfig() (portscan.Config, PortScanLists, string, error) {
	opts := c.PortScan
	if opts == nil {
		d := DefaultPortScanOptions()
		opts = &d
	}
	cfg, lists, err := opts.ToPortScanConfig()
	source := opts.Source
	if source == "" {
		source = PortScanSourceAuto
	}
	return cfg, lists, source, err
}

// UnmarshalJSON fills the shipped defaults first, then overlays whatever the
// configuration file actually says.
//
// Without it, a PortScan block would be taken literally: every field the
// operator did not write would be the zero value, and `{"PortScan":
// {"Enabled": true}}` -- what the "Port Scan Detection" wiki page tells the
// reader to add -- would give ScoreThreshold 0, MaxSources 0 and
// DecayInterval "", a configuration the daemon refuses as invalid.
//
// The pointer fields keep their meaning: absent leaves the default in place,
// while an explicit [] or 0 is the operator saying so, which is the distinction
// they were made pointers for.
func (o *PortScanOptions) UnmarshalJSON(b []byte) error {
	// A distinct type, or this method would call itself.
	type plain PortScanOptions
	merged := plain(DefaultPortScanOptions())
	if err := json.Unmarshal(b, &merged); err != nil {
		return err
	}
	*o = PortScanOptions(merged)
	return nil
}
