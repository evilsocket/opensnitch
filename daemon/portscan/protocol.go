//go:build linux

package portscan

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

// anomalyNames maps each anomaly bit to a stable identifier used in the
// protobuf message and in the coverage report. Values are never repurposed.
var anomalyNames = []struct {
	bit  Anomaly
	name string
}{
	{AnomalyFragment, "ip-fragment"},
	{AnomalyExtHeaderChain, "ipv6-extension-header-chain"},
	{AnomalyTruncated, "truncated-header"},
	{AnomalyNoTCPOptions, "syn-without-tcp-options"},
	{AnomalyFirstFragment, "ip-first-fragment"},
	{AnomalyVLANDepth, "vlan-stack-too-deep"},
	{AnomalyTrailer, "trailing-bytes-after-payload"},
}

// AnomalyStrings renders an anomaly mask as stable identifiers.
func AnomalyStrings(a Anomaly) []string {
	out := make([]string, 0, len(anomalyNames))
	for _, n := range anomalyNames {
		if a&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

// formatMAC renders a hardware address, or the empty string when none was
// observed.
func formatMAC(mac [6]byte, has bool) string {
	if !has {
		return ""
	}
	return net.HardwareAddr(mac[:]).String()
}

// ToProtocol converts a ScanEvent into the message sent to the user interface.
//
// ifaceName may be empty; the caller resolves the index when it can, because
// this package has no business holding an interface cache.
//
// The conversion carries the honesty constraints of the event through to the
// wire: MACIsSourceOwn travels with the MAC so a client cannot present a
// router's address as the scanner's, and SuppressedSince travels so a client
// cannot present one scan as the only one in progress.
func ToProtocol(ev *ScanEvent, ifaceName string, blockDuration time.Duration) *protocol.PortScan {
	if ev == nil {
		return nil
	}
	ports := make([]uint32, 0, len(ev.SamplePorts))
	for _, p := range ev.SamplePorts {
		ports = append(ports, uint32(p))
	}
	targets := make([]string, 0, len(ev.Targets))
	for _, t := range ev.Targets {
		targets = append(targets, t.String())
	}
	out := &protocol.PortScan{
		SrcIp:                ev.Src.String(),
		SrcMac:               formatMAC(ev.SrcMAC, ev.HasMAC),
		SrcMacIsSourceOwn:    ev.MACIsSourceOwn,
		Method:               ev.Method.String(),
		MethodDetail:         ev.MethodDetail,
		FlagsSummary:         ev.FlagsSummary,
		DistinctPorts:        ev.DistinctPorts,
		MinPort:              uint32(ev.MinPort),
		MaxPort:              uint32(ev.MaxPort),
		SamplePorts:          ports,
		Protocols:            uint32(ev.Protocols),
		IsProtocolScan:       ev.IsProtocolScan,
		Score:                ev.Score,
		Interface:            ifaceName,
		Targets:              targets,
		Anomalies:            AnomalyStrings(ev.Anomalies),
		HasTcpEvidence:       ev.HasTCPEvidence,
		BlockEligible:        ev.BlockEligible,
		SuppressedSince:      ev.SuppressedSince,
		BlockDurationSeconds: uint32(blockDuration / time.Second),
	}
	if !ev.FirstSeen.IsZero() {
		out.FirstSeenUnixnano = ev.FirstSeen.UnixNano()
	}
	if !ev.LastSeen.IsZero() {
		out.LastSeenUnixnano = ev.LastSeen.UnixNano()
	}
	return out
}

// Summary renders a scan as one line of prose for a desktop notification or a
// log entry.
//
// It is deliberately conservative about what it asserts. The source is
// described as "from <address>", never as "attacker": with decoys, spoofing,
// an idle scan or an FTP bounce, that address belongs to someone uninvolved.
// The MAC is only shown when it is the source's own.
func Summary(ev *ScanEvent, outcome BlockOutcome, blockDuration time.Duration) (title, body string) {
	title = "Port scan detected"

	var b strings.Builder
	fmt.Fprintf(&b, "%s from %s", ev.MethodDetail, ev.Src)
	if ev.MACIsSourceOwn && ev.HasMAC {
		fmt.Fprintf(&b, " (%s)", formatMAC(ev.SrcMAC, true))
	} else if ev.HasMAC {
		// Saying whose address it is matters: presenting a router's MAC as the
		// scanner's would be an attribution the packets do not support.
		fmt.Fprintf(&b, " (last hop %s)", formatMAC(ev.SrcMAC, true))
	}
	b.WriteString("\n")

	if ev.IsProtocolScan {
		fmt.Fprintf(&b, "%d distinct IP protocols probed", ev.Protocols)
	} else {
		fmt.Fprintf(&b, "%d ports probed", ev.DistinctPorts)
		if ev.DistinctPorts > 1 {
			fmt.Fprintf(&b, " between %d and %d", ev.MinPort, ev.MaxPort)
		}
	}
	if ev.FlagsSummary != "" {
		fmt.Fprintf(&b, ", TCP flags %s", ev.FlagsSummary)
	}
	if anom := AnomalyStrings(ev.Anomalies); len(anom) > 0 {
		fmt.Fprintf(&b, "\nEvasion signs: %s", strings.Join(anom, ", "))
	}

	switch outcome {
	case OutcomeApplied:
		fmt.Fprintf(&b, "\nBlocked for %s.", formatDuration(blockDuration))
	case OutcomeProposed:
		fmt.Fprintf(&b, "\nBlock this source for %s?", formatDuration(blockDuration))
	case OutcomeRefused:
		b.WriteString("\nNot blocked.")
	}

	if ev.SuppressedSince > 0 {
		// Without this line the user would believe a single host is scanning
		// them, when a decoy scan or a spoofed-source scan is in progress.
		fmt.Fprintf(&b, "\n%d further scan alert(s) were suppressed to avoid flooding.", ev.SuppressedSince)
	}
	return title, b.String()
}

func formatDuration(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	default:
		return d.String()
	}
}
