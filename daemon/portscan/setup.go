//go:build linux

package portscan

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Source selectors, mirroring the values accepted in the configuration file.
const (
	SourceAuto     = "auto"
	SourceEbpf     = "ebpf"
	SourceAFPacket = "afpacket"
)

// SetupOptions is what the daemon passes to Setup.
type SetupOptions struct {
	Config Config
	// Source is "auto", "ebpf" or "afpacket".
	Source string
	// ModulesPath overrides where the eBPF object is looked for.
	ModulesPath string
	// NeverCount suppresses detection entirely for these prefixes.
	NeverCount []netip.Prefix
	// NeverBlock forbids a firewall rule against these prefixes, while leaving
	// detection active for them.
	NeverBlock []netip.Prefix

	// Report receives every surfaced scan.
	Report ReportFunc
	// OnError receives non-fatal errors, including the notice that the eBPF
	// path was unavailable and the fallback was used.
	OnError func(error)
	// EnableBlocking builds the nftables backend. Set false to run detection
	// without ever touching the firewall.
	EnableBlocking bool
}

// Setup builds a ready-to-start Monitor, choosing the packet source.
//
// The choice is reported through OnError when it is not the one asked for, so
// that "detection is running" never quietly means "running at ten times the
// cost you expected" or, worse, "not running at all".
func Setup(opts SetupOptions) (*Monitor, string, error) {
	if opts.OnError == nil {
		opts.OnError = func(error) {}
	}
	source := opts.Source
	if source == "" {
		source = SourceAuto
	}

	// chosen is written by the factory below, so the caller learns which path
	// actually came up rather than which one was requested.
	chosen := ""

	newSource := func(host *SystemHostInfo, onProbe func(*Probe), onErr func(error)) (PacketSource, error) {
		tryEbpf := func() (PacketSource, error) {
			return NewEbpfSource(EbpfOptions{
				ModulesPath:        opts.ModulesPath,
				Interfaces:         opts.Config.Interfaces,
				StartupGrace:       opts.Config.StartupGrace,
				ExcludedPorts:      opts.Config.ExcludedPorts,
				MaxProbesPerSecond: 256,
				// Both of these are load-bearing, not optimisations. The eBPF
				// program keeps a packet aimed at one of our own addresses and
				// discards everything else, so an unseeded local address map
				// means it discards every packet and detection runs blind.
				// The exemption trie spares the ring buffer the traffic
				// userspace would only throw away.
				LocalAddrs: host.LocalAddrs(),
				Exempt:     host.ExemptPrefixes(),
			}, onProbe, onErr)
		}
		tryAFPacket := func() (PacketSource, error) {
			return NewAFPacketSource(opts.Config.Interfaces, afPacketDefaultBudget, onProbe, onErr)
		}
		s, name, err := selectSource(source, tryEbpf, tryAFPacket, opts.OnError)
		chosen = name
		return s, err
	}

	mopts := MonitorOptions{
		Config:     opts.Config,
		NeverCount: opts.NeverCount,
		NeverBlock: opts.NeverBlock,
		Report:     opts.Report,
		NewSource:  newSource,
		OnError:    opts.OnError,
	}
	if opts.EnableBlocking {
		mopts.NewBlocker = func(d time.Duration) (Blocker, error) { return NewNftBlocker(d) }
	}

	m, err := NewMonitor(mopts)
	if err != nil {
		return nil, chosen, err
	}
	return m, chosen, nil
}

// selectSource applies the packet-source policy.
//
// It is separated from Setup so the decision can be tested without the
// privileges a real packet source needs: the two constructors are the only
// thing Setup adds, and getting the choice wrong is the failure that matters
// -- a daemon silently running the expensive path, or not running at all.
func selectSource(requested string, tryEbpf, tryAFPacket func() (PacketSource, error), onError func(error)) (PacketSource, string, error) {
	switch requested {
	case SourceEbpf:
		s, err := tryEbpf()
		if err != nil {
			// The operator asked for eBPF explicitly. Falling back silently
			// would give them a performance profile they did not choose, so
			// this fails instead.
			return nil, "", err
		}
		return s, SourceEbpf, nil

	case SourceAFPacket:
		s, err := tryAFPacket()
		if err != nil {
			return nil, "", err
		}
		return s, SourceAFPacket, nil

	case "", SourceAuto:
		s, err := tryEbpf()
		if err == nil {
			return s, SourceEbpf, nil
		}
		if errors.Is(err, ErrNoConfiguredInterface) {
			// AF_PACKET would refuse the same list; announcing a fallback to
			// it first would only bury the real cause under a degradation.
			return nil, "", err
		}
		onError(degraded("the eBPF path is unavailable (%w); falling back to AF_PACKET, which costs more CPU per packet", err))
		s, ferr := tryAFPacket()
		if ferr != nil {
			return nil, "", fmt.Errorf("portscan: neither packet source is usable: eBPF: %v; AF_PACKET: %w", err, ferr)
		}
		return s, SourceAFPacket, nil

	default:
		// An unrecognised selector is refused rather than quietly treated as
		// "auto": a typo in the configuration must not decide which packet
		// source runs. The configuration layer rejects it too; this is the
		// backstop for any caller that bypasses it.
		return nil, "", fmt.Errorf("portscan: unknown packet source %q (want %q, %q or %q)",
			requested, SourceAuto, SourceEbpf, SourceAFPacket)
	}
}

// IsEbpfUnavailable reports whether err is the eBPF path being unusable, so a
// caller can log it as an expected condition rather than a fault.
func IsEbpfUnavailable(err error) bool { return errors.Is(err, ErrEbpfUnavailable) }

// InterfaceName resolves an interface index for reporting.
func InterfaceName(idx uint32) string { return interfaceName(idx) }
