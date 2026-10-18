package portscan

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Parsing errors. They are values, not formatted strings, so the hot path
// allocates nothing when a packet is rejected.
var (
	// ErrTooShort means the frame ended before a header it claims to contain.
	ErrTooShort = errors.New("portscan: packet too short")
	// ErrNotIP means the frame is not IPv4 or IPv6 (ARP, LLDP, ...).
	ErrNotIP = errors.New("portscan: not an IP packet")
	// ErrUnsupportedLinkType means the capture link layer is not handled.
	ErrUnsupportedLinkType = errors.New("portscan: unsupported link type")
	// ErrNoTransport means the packet carries no TCP or UDP header that could
	// be read. The probe is still usable for protocol-scan counting.
	ErrNoTransport = errors.New("portscan: no readable transport header")
)

// Ethernet constants.
const (
	ethHeaderLen = 14
	ethTypeIPv4  = 0x0800
	ethTypeIPv6  = 0x86DD
	ethTypeVLAN  = 0x8100
	ethTypeQinQ  = 0x88A8
	vlanTagLen   = 4
	maxVLANTags  = 2
)

// maxExtHeaders bounds the IPv6 extension header walk. An eBPF program cannot
// loop without a bound, so kernel and user space share this one. Exceeding it is
// reported as AnomalyExtHeaderChain: a long chain is itself an evasion
// signature (Topera; psad:1709).
const maxExtHeaders = 8

// maxExtChainBytes bounds the total length of the extension chain as well:
// one Destination Options header may be 2048 bytes, so a header count alone
// bounds nothing useful. It decides how much of a frame the AF_PACKET path
// copies (afPacketSnapLen), and is far more than any legitimate chain. The C
// program carries the same constant (TestSharedParserBoundsMatchC).
const maxExtChainBytes = 1024

// IPv6 extension header numbers, per the IANA "Protocol Numbers" registry and
// RFC 8200 section 4.1.
const (
	ipv6ExtHopByHop  = 0
	ipv6ExtRouting   = 43
	ipv6ExtFragment  = 44
	ipv6ExtESP       = 50
	ipv6ExtAH        = 51
	ipv6NoNextHeader = 59
	ipv6ExtDestOpts  = 60
	ipv6ExtMobility  = 135
	ipv6ExtHIP       = 139
	ipv6ExtShim6     = 140
)

// isIPv6ExtHeader reports whether a next-header value introduces an extension
// header whose length can be determined and skipped. ESP (50) is absent:
// everything after it is encrypted, and parsing ciphertext as TCP is wrong.
func isIPv6ExtHeader(nh uint8) bool {
	switch nh {
	case ipv6ExtHopByHop, ipv6ExtRouting, ipv6ExtFragment, ipv6ExtAH,
		ipv6ExtDestOpts, ipv6ExtMobility, ipv6ExtHIP, ipv6ExtShim6:
		return true
	default:
		return false
	}
}

// extHeaderLen returns the total length in bytes of an IPv6 extension header
// whose first two octets are nextHeader and hdrExtLen. Three conventions
// coexist:
//
//   - most headers: (hdrExtLen+1)*8, so 0 is a valid 8-byte header (RFC 8200
//     4.3) -- PortSentry discards such packets;
//   - Fragment: a fixed 8 octets, its second byte reserved (RFC 8200 4.5);
//   - Authentication Header: (hdrExtLen+2)*4 (RFC 4302 2.2).
func extHeaderLen(nextHeader, hdrExtLen uint8) int {
	switch nextHeader {
	case ipv6ExtFragment:
		return 8
	case ipv6ExtAH:
		return (int(hdrExtLen) + 2) * 4
	default:
		return (int(hdrExtLen) + 1) * 8
	}
}

// ParseEthernet fills p from a complete Ethernet frame.
//
// VLAN tags are unwrapped (up to maxVLANTags, covering 802.1Q and QinQ) so
// that tagged traffic is not silently invisible to detection.
func ParseEthernet(frame []byte, p *Probe) error {
	if len(frame) < ethHeaderLen {
		return ErrTooShort
	}
	copy(p.SrcMAC[:], frame[6:12])
	p.HasMAC = true

	etherType := binary.BigEndian.Uint16(frame[12:14])
	off := ethHeaderLen
	for tags := 0; (etherType == ethTypeVLAN || etherType == ethTypeQinQ) && tags < maxVLANTags; tags++ {
		if len(frame) < off+vlanTagLen {
			return ErrTooShort
		}
		etherType = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += vlanTagLen
	}

	switch etherType {
	case ethTypeIPv4, ethTypeIPv6:
		return ParseIP(frame[off:], p)
	case ethTypeVLAN, ethTypeQinQ:
		// The stack is deeper than the bounded unwrap: reported, not treated as "not
		// IP", which is what VLAN hopping counts on.
		p.Anomalies |= AnomalyVLANDepth
		return ErrNotIP
	default:
		return ErrNotIP
	}
}

// ParseIP fills p from an IPv4 or IPv6 packet, transport header included when
// one can be read. ErrNoTransport means the addresses and protocol were
// recovered but not the transport header (a non-initial fragment, an encrypted
// payload, a protocol without ports); such a probe still counts towards the
// distinct-protocol total of an nmap -sO scan, and still carries its anomalies.
func ParseIP(pkt []byte, p *Probe) error {
	if len(pkt) < 1 {
		return ErrTooShort
	}
	switch pkt[0] >> 4 {
	case 4:
		return parseIPv4(pkt, p)
	case 6:
		return parseIPv6(pkt, p)
	default:
		return ErrNotIP
	}
}

func parseIPv4(pkt []byte, p *Probe) error {
	const minIPv4 = 20
	if len(pkt) < minIPv4 {
		p.Anomalies |= AnomalyTruncated
		return ErrTooShort
	}
	ihl := int(pkt[0]&0x0f) * 4
	// A header shorter than the minimum is malformed; trusting it would make
	// the transport offset point inside the IP header itself. flowhawk
	// computes the L4 offset from ihl without ever checking it
	// (packet_monitor.c:169).
	if ihl < minIPv4 {
		p.Anomalies |= AnomalyTruncated
		return ErrTooShort
	}

	p.Src = netip.AddrFrom4([4]byte(pkt[12:16]))
	p.Dst = netip.AddrFrom4([4]byte(pkt[16:20]))
	p.Proto = pkt[9]

	flagsFrag := binary.BigEndian.Uint16(pkt[6:8])
	if fragOff := flagsFrag & 0x1fff; fragOff != 0 {
		// A non-initial fragment has no transport header at any assumed
		// offset. scanlogd refuses these explicitly (scanlogd.c:208); reading
		// on would interpret payload bytes as ports and flags.
		p.Anomalies |= AnomalyFragment
		return ErrNoTransport
	}
	if flagsFrag&0x2000 != 0 {
		// More Fragments on the first fragment. The ports are here, so this is
		// still counted -- that is what makes nmap -f detectable -- but the
		// fact that the datagram was split is evidence in its own right and
		// must survive to the report.
		p.Anomalies |= AnomalyFirstFragment
	}

	// The header declares options that did not arrive. Everything the first 20
	// bytes carry is already recovered, and the probe is kept with the anomaly --
	// dropping it would make an IHL of 15 an evasion. The kernel program keeps the
	// record too.
	if ihl > len(pkt) {
		p.Anomalies |= AnomalyTruncated
		return ErrNoTransport
	}

	return parseTransport(ipPayload(pkt, ihl, int(binary.BigEndian.Uint16(pkt[2:4])), p), p)
}

// ipPayload returns the transport bytes, bounded by the length the IP header
// declares rather than by what the frame contains. Ethernet pads short frames,
// and nmap -f's 28-byte datagrams arrive with padding that routers regenerate:
// read as TCP, zero padding is a NULL scan, and a trailer an on-link sender
// chooses sets the flags. declared is the total length for IPv4, or
// 40+PayloadLength for IPv6; a shorter frame is a truncated capture, a longer
// one carries a trailer.
func ipPayload(pkt []byte, headerLen, declared int, p *Probe) []byte {
	switch {
	case declared < headerLen:
		// A length shorter than the header it describes is malformed. Trusting
		// it would produce a negative slice bound.
		p.Anomalies |= AnomalyTruncated
		return nil
	case declared > len(pkt):
		// The capture is shorter than the datagram claims: a snaplen cut, or a
		// lying header. Either way only the captured bytes exist.
		p.Anomalies |= AnomalyTruncated
		return pkt[headerLen:]
	case declared < len(pkt):
		p.Anomalies |= AnomalyTrailer
		return pkt[headerLen:declared]
	default:
		return pkt[headerLen:declared]
	}
}

func parseIPv6(pkt []byte, p *Probe) error {
	const ipv6HeaderLen = 40
	if len(pkt) < ipv6HeaderLen {
		p.Anomalies |= AnomalyTruncated
		return ErrTooShort
	}
	src := netip.AddrFrom16([16]byte(pkt[8:24]))
	dst := netip.AddrFrom16([16]byte(pkt[24:40]))

	// An IPv4-mapped address inside an IPv6 packet is refused, on either side of
	// the header. RFC 4291 2.5.5.2 keeps the form off the wire, and Linux drops such
	// a packet, so it probes nothing; kept, it would let an on-link sender who
	// cannot spoof IPv4 have any IPv4 address blocked. No compliant stack emits it.
	if src.Is4In6() || dst.Is4In6() {
		return ErrNotIP
	}
	p.Src = src
	p.Dst = dst

	// Bound the packet by the length the header declares before walking anything
	// (see ipPayload). Payload Length zero with a Hop-by-Hop header is the
	// exception the kernel makes -- ip6_rcv_core() trims only when (pkt_len ||
	// nexthdr != NEXTHDR_HOP) -- so that shape reaches TCP and is answered; the
	// captured length is used for it, and recorded.
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if payloadLen == 0 && pkt[6] == ipv6ExtHopByHop {
		p.Anomalies |= AnomalyExtHeaderChain
	} else {
		declared := ipv6HeaderLen + payloadLen
		bounded := ipPayload(pkt, ipv6HeaderLen, declared, p)
		if bounded == nil {
			return ErrTooShort
		}
		pkt = pkt[:ipv6HeaderLen+len(bounded)]
	}

	next := pkt[6]
	off := ipv6HeaderLen

	for hops := 0; ; hops++ {
		if !isIPv6ExtHeader(next) {
			break
		}
		if hops >= maxExtHeaders || off-ipv6HeaderLen >= maxExtChainBytes {
			// Bounded walk exhausted. Report it: a chain this long is an
			// evasion attempt, not ordinary traffic.
			p.Anomalies |= AnomalyExtHeaderChain
			p.Proto = next
			return ErrNoTransport
		}
		if off+2 > len(pkt) {
			p.Anomalies |= AnomalyTruncated
			p.Proto = next
			return ErrTooShort
		}
		hdrNext, hdrExtLen := pkt[off], pkt[off+1]
		length := extHeaderLen(next, hdrExtLen)

		if next == ipv6ExtFragment {
			if off+4 > len(pkt) {
				p.Anomalies |= AnomalyTruncated
				p.Proto = next
				return ErrTooShort
			}
			fragOff := binary.BigEndian.Uint16(pkt[off+2:off+4]) >> 3
			if fragOff != 0 {
				p.Anomalies |= AnomalyFragment
				p.Proto = hdrNext
				return ErrNoTransport
			}
		}

		// The end of the chain is bounded, not only where each header starts: one
		// header may be 2048 bytes, and a chain ending past the bound would put the TCP
		// header beyond afPacketSnapLen, visible to the kernel path and not to
		// AF_PACKET. Checked before truncation so both paths, one of which holds only
		// afPacketSnapLen bytes, reach the same verdict.
		if length > 0 && off+length-ipv6HeaderLen > maxExtChainBytes {
			p.Anomalies |= AnomalyExtHeaderChain
			p.Proto = next
			return ErrNoTransport
		}
		if length <= 0 || off+length > len(pkt) {
			p.Anomalies |= AnomalyTruncated
			p.Proto = next
			return ErrTooShort
		}
		off += length
		next = hdrNext
	}

	p.Proto = next
	if next == ipv6NoNextHeader {
		return ErrNoTransport
	}
	return parseTransport(pkt[off:], p)
}

// parseTransport reads the TCP or UDP header. p.Proto must already be set.
func parseTransport(rest []byte, p *Probe) error {
	switch p.Proto {
	case ProtoTCP:
		const minTCP = 20
		if len(rest) < minTCP {
			// A first fragment from nmap -f carries only the first eight bytes of the TCP
			// header: the ports, not the flags. The ports are read and the missing flags
			// recorded, which is what makes a fragmented scan detectable.
			p.Anomalies |= AnomalyTruncated
			if len(rest) < 4 {
				return ErrTooShort
			}
			p.SrcPort = binary.BigEndian.Uint16(rest[0:2])
			p.DstPort = binary.BigEndian.Uint16(rest[2:4])
			if len(rest) >= 14 {
				p.TCPFlags = rest[13]
				p.TCPFlagsValid = true
			}
			return nil
		}
		p.SrcPort = binary.BigEndian.Uint16(rest[0:2])
		p.DstPort = binary.BigEndian.Uint16(rest[2:4])
		// The whole 13th octet, kept verbatim. Reconstructing a subset here
		// would destroy the ability to tell an Xmas scan from a FIN scan.
		p.TCPFlags = rest[13]
		p.TCPFlagsValid = true

		dataOff := int(rest[12]>>4) * 4
		if dataOff < minTCP || dataOff > len(rest) {
			p.Anomalies |= AnomalyTruncated
			return nil
		}
		// A SYN carrying no options at all is not what a real stack emits: it
		// always advertises at least an MSS. psad uses the same signal to
		// recognise masscan (psad:1801-1807).
		if p.TCPFlags&TCPSyn != 0 && dataOff == minTCP {
			p.Anomalies |= AnomalyNoTCPOptions
		}
		return nil

	case ProtoUDP:
		const minUDP = 8
		if len(rest) < minUDP {
			p.Anomalies |= AnomalyTruncated
			return ErrTooShort
		}
		p.SrcPort = binary.BigEndian.Uint16(rest[0:2])
		p.DstPort = binary.BigEndian.Uint16(rest[2:4])
		return nil

	case ProtoICMP, ProtoICMPv6:
		// The message type and code, carried in DstPort as type<<8|code. See
		// Probe.ICMPType: the engine deduplicates scored probes by that field, so
		// putting the type there is what makes an ICMP source worth one score per
		// distinct message type rather than one per packet.
		const minICMP = 2
		if len(rest) < minICMP {
			p.Anomalies |= AnomalyTruncated
			return ErrTooShort
		}
		p.DstPort = uint16(rest[0])<<8 | uint16(rest[1])
		return nil

	default:
		// Any other IP protocol has no ports. It is still meaningful: an
		// nmap -sO scan is exactly a stream of these, and the engine counts
		// distinct protocol numbers to detect it.
		return ErrNoTransport
	}
}
