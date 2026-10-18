// Package portscan detects inbound port scans against the local host.
//
// It has two halves:
//
//   - a pure, allocation-free detection Engine (probe.go, state.go, engine.go,
//     method.go) that consumes normalised Probe observations and emits
//     ScanEvent verdicts, testable without any privilege;
//   - packet sources (eBPF at TC ingress, or AF_PACKET as a fallback) that turn
//     real packets into Probes.
//
// The design, and what it takes from scanlogd, PortSentry, psad and
// Portmaster's unmerged PR #128, is described on the project wiki's "Port Scan
// Detection" pages.
package portscan

import (
	"net/netip"
)

// TCP control bits, in the wire order of the 13th octet of the TCP header. The
// raw octet is kept throughout: a partial flag set loses what names the
// technique (dropping PSH and URG makes an Xmas scan look like a FIN scan).
const (
	TCPFin uint8 = 1 << 0
	TCPSyn uint8 = 1 << 1
	TCPRst uint8 = 1 << 2
	TCPPsh uint8 = 1 << 3
	TCPAck uint8 = 1 << 4
	TCPUrg uint8 = 1 << 5
	TCPEce uint8 = 1 << 6
	TCPCwr uint8 = 1 << 7
)

// IP protocol numbers the engine reasons about explicitly.
const (
	ProtoICMP   uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
	ProtoSCTP   uint8 = 132
)

// Anomaly is a bitmask of packet-level oddities observed by the packet source.
// They are reported rather than dropped: an evasion attempt is itself evidence,
// and tools like Topera count on analysers giving up quietly.
type Anomaly uint16

// Anomaly values.
const (
	// AnomalyFragment is set for a non-initial IP fragment, whose L4 header
	// cannot be read at any assumed offset. scanlogd rejects these outright
	// (scanlogd.c:208); we count them separately instead of ignoring them.
	AnomalyFragment Anomaly = 1 << iota
	// AnomalyExtHeaderChain is set when the IPv6 extension header chain
	// exceeded the bounded walk limit.
	AnomalyExtHeaderChain
	// AnomalyTruncated is set when the packet was too short to hold the
	// headers its own fields claim.
	AnomalyTruncated
	// AnomalyNoTCPOptions is set for a TCP SYN carrying no options at all.
	// A real stack always advertises at least an MSS; its absence points to a
	// raw packet generator such as masscan (psad:1801-1807).
	AnomalyNoTCPOptions

	// AnomalyFirstFragment is set for the first fragment of a fragmented datagram.
	// Unlike a non-initial fragment, which has no transport header and is
	// discarded, it carries the ports and still counts: that is what makes nmap -f
	// detectable.
	AnomalyFirstFragment

	// AnomalyVLANDepth is set when the VLAN tag stack was deeper than the bounded
	// unwrap: a triple-tagged frame is VLAN hopping, not ordinary traffic.
	AnomalyVLANDepth

	// AnomalyTrailer is set when the frame carried bytes after the payload the IP
	// header declares. Ethernet pads short frames, so this is common; what matters
	// is that the parser never reads those bytes as part of the datagram.
	AnomalyTrailer

	// lastAnomalyBit is the highest bit defined above. It must be updated when
	// a value is added: TestEveryAnomalyBitHasAName uses it to insist that
	// every bit also has a reported identifier, so that a new anomaly cannot be
	// observed by the packet source yet stay invisible to the user.
	lastAnomalyBit = AnomalyTrailer
)

// Probe is one normalised observation of an inbound packet: a flat value with
// no slice or map in it, so the hot path allocates nothing.
//
// A Probe handed to an onProbe callback is valid only during that call: both
// sources reuse one Probe for their whole read loop, so the sender does not
// choose how often the garbage collector runs. A callback that keeps a probe
// copies it.
type Probe struct {
	// TimeNs is a CLOCK_MONOTONIC timestamp in nanoseconds, never wall-clock, so
	// an NTP step or a resume cannot corrupt the window arithmetic (as scanlogd,
	// scanlogd.c:221-223).
	TimeNs uint64

	// Src is the source address of the packet, as seen on the wire.
	// It is attacker-controlled and may be spoofed; see ScanEvent.
	Src netip.Addr
	// Dst is the destination address, used to verify that the packet is
	// actually addressed to one of our unicast addresses.
	Dst netip.Addr

	// SrcMAC is the link-layer source address, which is the address of the
	// previous hop, not necessarily of the scanner. HasMAC reports whether it
	// was available at all (it is not, for instance, on a point-to-point
	// tunnel, or when the packet source cannot see layer 2).
	SrcMAC [6]byte
	HasMAC bool

	// Proto is the IP protocol number (6 TCP, 17 UDP, 132 SCTP, ...).
	Proto uint8
	// TCPFlags is the raw 13th octet of the TCP header. Zero for non-TCP.
	TCPFlags uint8
	// TCPFlagsValid reports that TCPFlags was actually read. A NULL scan sets no
	// bits and nmap -f's first fragment stops before the flags; without this the
	// engine would report a NULL scan for flags it never saw.
	TCPFlagsValid bool

	SrcPort uint16
	DstPort uint16

	// IfaceIndex identifies the receiving interface.
	IfaceIndex uint32

	Anomalies Anomaly
}

// IsTCP reports whether the probe carries a TCP header.
func (p *Probe) IsTCP() bool { return p.Proto == ProtoTCP }

// IsUDP reports whether the probe carries a UDP header.
func (p *Probe) IsUDP() bool { return p.Proto == ProtoUDP }

// hasFlags reports whether every bit in mask is set in the probe's TCP flags.
func (p *Probe) hasFlags(mask uint8) bool { return p.TCPFlags&mask == mask }

// hasAnyFlag reports whether at least one bit in mask is set.
func (p *Probe) hasAnyFlag(mask uint8) bool { return p.TCPFlags&mask != 0 }

// PortClass is the IANA range a destination port falls into. A system port is
// stronger evidence than an ephemeral one, where return traffic and
// peer-to-peer applications live -- scanlogd's weighting against passive FTP
// (params.h:52-53), refined to three levels by Portmaster.
type PortClass uint8

// Port classes.
const (
	// PortSystem is 1-1023, the IANA System (well-known) range.
	PortSystem PortClass = iota
	// PortRegistered is 1024-49151, the IANA User (registered) range.
	PortRegistered
	// PortDynamic is 49152-65535, the IANA Dynamic/ephemeral range.
	PortDynamic
)

// registeredPortsStart and dynamicPortsStart follow RFC 6335 section 6. The
// Linux ephemeral range is handled explicitly where it matters, so these mean
// what their names say.
const (
	registeredPortsStart = 1024
	dynamicPortsStart    = 49152
)

// ClassifyPort returns the IANA range of a destination port.
func ClassifyPort(port uint16) PortClass {
	if _, ok := highValuePorts[port]; ok {
		return PortSystem
	}
	switch {
	case port < registeredPortsStart:
		return PortSystem
	case port < dynamicPortsStart:
		return PortRegistered
	default:
		return PortDynamic
	}
}

// highValuePorts are ports an attacker cares about that IANA registered above
// 1024 -- remote desktop, database engines, VNC, Redis -- which the ranges alone
// would weight as ordinary registered ports, letting a sweep of exactly the
// services that matter stay under the threshold. A short list of services
// whose exposure is a finding in any assessment, not a service catalogue.
var highValuePorts = map[uint16]struct{}{
	1433:  {}, // Microsoft SQL Server
	1521:  {}, // Oracle TNS listener
	2375:  {}, // Docker daemon, unencrypted
	2376:  {}, // Docker daemon, TLS
	3306:  {}, // MySQL / MariaDB
	3389:  {}, // RDP
	5432:  {}, // PostgreSQL
	5900:  {}, // VNC
	5901:  {}, // VNC, second display
	6379:  {}, // Redis
	9200:  {}, // Elasticsearch
	11211: {}, // memcached
	27017: {}, // MongoDB
}

// String implements fmt.Stringer.
func (c PortClass) String() string {
	switch c {
	case PortSystem:
		return "system"
	case PortRegistered:
		return "registered"
	case PortDynamic:
		return "dynamic"
	default:
		return "unknown"
	}
}

// IsICMP reports whether the probe carries an ICMP or ICMPv6 header.
func (p *Probe) IsICMP() bool { return p.Proto == ProtoICMP || p.Proto == ProtoICMPv6 }

// ICMPType and ICMPCode read the message type and code of an ICMP probe,
// packed in DstPort as type<<8|code, the convention the kernel's connection
// tracking uses. The engine deduplicates scored probes by (protocol, DstPort),
// so an ICMP source is scored once per distinct type, however many packets it
// sends. Meaningless unless IsICMP.
func (p *Probe) ICMPType() uint8 { return uint8(p.DstPort >> 8) }
func (p *Probe) ICMPCode() uint8 { return uint8(p.DstPort) }

// IsICMPSweepProbe reports whether this ICMP message is a query a host sweep is
// made of. Replies and errors are what this host asked for -- a traceroute
// through a router that is not the gateway brings Time Exceeded, Destination
// Unreachable and Echo Reply -- and unassigned types mean nothing; counting
// either would let three packets accuse any address. The set is what a sweep
// sends and nothing else does:
//
//	8   Echo Request         nmap -PE
//	13  Timestamp Request    nmap -PP
//	17  Address Mask Request nmap -PM
//	15  Information Request  dead since RFC 1122, scanners only
//	128 Echo Request (v6)    nmap -PE over IPv6
//	139 Node Information Query  RFC 4620, the RFC 7707 address-harvesting probe
//
// Echo request is in the set but scores nothing on its own (see
// weightICMPRecon). Types are read per address family: type 3 means different
// things in ICMP and ICMPv6.
func (p *Probe) IsICMPSweepProbe() bool {
	switch p.Proto {
	case ProtoICMP:
		switch p.ICMPType() {
		case icmpv4Echo, icmpv4Timestamp, icmpv4Information, icmpv4AddressMask:
			return true
		}
	case ProtoICMPv6:
		switch p.ICMPType() {
		case icmpv6Echo, icmpv6NodeInfoQuery:
			return true
		}
	}
	return false
}

// icmpSweepThreshold is the configured minimum, capped at what the family
// can produce (icmpSweepTypesFor), so it can never be unsatisfiable. One
// number covers both families, and raising it to tighten IPv4 must not switch
// IPv6 detection off.
func icmpSweepThreshold(configured uint16, proto uint8) uint16 {
	if n := icmpSweepTypesFor(proto); n != 0 && configured > n {
		return n
	}
	return configured
}

// icmpSweepTypesFor is how many distinct query types the probe's family has:
// four for IPv4, two for IPv6, where every other query is also ordinary link
// traffic. It is the most the counter can reach.
func icmpSweepTypesFor(proto uint8) uint16 {
	switch proto {
	case ProtoICMP:
		return 4 // echo, timestamp, information, address mask
	case ProtoICMPv6:
		return 2 // echo, node information query
	}
	return 0
}
