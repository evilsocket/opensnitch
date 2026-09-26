package portscan

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// ---------------------------------------------------------------------------
// packet builders
//
// Frames are assembled byte by byte rather than with a packet library, so the
// test states exactly what is on the wire and cannot inherit a library's
// interpretation of the same specification the parser is being checked against.
// ---------------------------------------------------------------------------

var (
	srcMACBytes = [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	dstMACBytes = [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
)

func be16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// ethFrame wraps a payload in an Ethernet header, optionally with VLAN tags.
func ethFrame(etherType uint16, vlans []uint16, payload []byte) []byte {
	f := make([]byte, 0, ethHeaderLen+len(vlans)*vlanTagLen+len(payload))
	f = append(f, dstMACBytes[:]...)
	f = append(f, srcMACBytes[:]...)
	for _, vid := range vlans {
		f = append(f, be16(ethTypeVLAN)...)
		f = append(f, be16(vid)...)
	}
	f = append(f, be16(etherType)...)
	return append(f, payload...)
}

// ipv4Packet builds an IPv4 header of ihl*4 bytes. fragOff is in 8-octet units.
func ipv4Packet(proto uint8, src, dst netip.Addr, fragOff uint16, moreFragments bool, payload []byte) []byte {
	const ihl = 5
	h := make([]byte, ihl*4)
	h[0] = 4<<4 | ihl
	binary.BigEndian.PutUint16(h[2:4], uint16(len(h)+len(payload)))
	flags := fragOff
	if moreFragments {
		flags |= 1 << 13
	}
	binary.BigEndian.PutUint16(h[6:8], flags)
	h[8] = 64
	h[9] = proto
	copy(h[12:16], src.AsSlice())
	copy(h[16:20], dst.AsSlice())
	return append(h, payload...)
}

// ipv6Packet builds a 40-byte IPv6 header followed by payload.
func ipv6Packet(nextHeader uint8, src, dst netip.Addr, payload []byte) []byte {
	h := make([]byte, 40)
	h[0] = 6 << 4
	binary.BigEndian.PutUint16(h[4:6], uint16(len(payload)))
	h[6] = nextHeader
	h[7] = 64
	copy(h[8:24], src.AsSlice())
	copy(h[24:40], dst.AsSlice())
	return append(h, payload...)
}

// tcpHeader builds a TCP header of dataOff*4 bytes (dataOff in 32-bit words).
func tcpHeader(srcPort, dstPort uint16, flags uint8, dataOff int) []byte {
	h := make([]byte, dataOff*4)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	h[12] = byte(dataOff) << 4
	h[13] = flags
	return h
}

func udpHeader(srcPort, dstPort uint16) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	binary.BigEndian.PutUint16(h[4:6], 8)
	return h
}

// extHeader builds a generic 8-octet-unit extension header of the given total
// length, whose Hdr Ext Len field is derived from that length.
func extHeader(nextHeader uint8, totalLen int) []byte {
	h := make([]byte, totalLen)
	h[0] = nextHeader
	h[1] = byte(totalLen/8 - 1)
	return h
}

// ahHeader builds an Authentication Header of the given total length, whose
// Payload Len field counts 4-octet units minus 2 (RFC 4302 section 2.2).
func ahHeader(nextHeader uint8, totalLen int) []byte {
	h := make([]byte, totalLen)
	h[0] = nextHeader
	h[1] = byte(totalLen/4 - 2)
	return h
}

// fragHeader builds an 8-byte IPv6 Fragment header. offset is in 8-octet units.
func fragHeader(nextHeader uint8, offset uint16, more bool) []byte {
	h := make([]byte, 8)
	h[0] = nextHeader
	v := offset << 3
	if more {
		v |= 1
	}
	binary.BigEndian.PutUint16(h[2:4], v)
	return h
}

var (
	v4src = netip.MustParseAddr("192.0.2.66")
	v4dst = netip.MustParseAddr("192.0.2.1")
	v6src = netip.MustParseAddr("2001:db8::66")
	v6dst = netip.MustParseAddr("2001:db8::1")
)

// ---------------------------------------------------------------------------
// Ethernet
// ---------------------------------------------------------------------------

func TestParseEthernetIPv4(t *testing.T) {
	frame := ethFrame(ethTypeIPv4, nil,
		ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(40000, 22, TCPSyn, 5)))

	var p Probe
	if err := ParseEthernet(frame, &p); err != nil {
		t.Fatalf("ParseEthernet: %v", err)
	}
	if !p.HasMAC || p.SrcMAC != srcMACBytes {
		t.Fatalf("SrcMAC = %v (has=%v), want %v", p.SrcMAC, p.HasMAC, srcMACBytes)
	}
	if p.Src != v4src || p.Dst != v4dst {
		t.Fatalf("addresses = %s -> %s", p.Src, p.Dst)
	}
	if p.Proto != ProtoTCP || p.DstPort != 22 || p.SrcPort != 40000 {
		t.Fatalf("transport = proto %d, %d -> %d", p.Proto, p.SrcPort, p.DstPort)
	}
	if !p.TCPFlagsValid || p.TCPFlags != TCPSyn {
		t.Fatalf("flags = %#x (valid=%v)", p.TCPFlags, p.TCPFlagsValid)
	}
}

// TestParseEthernetVLAN: tagged traffic must not be silently invisible to
// detection. A scan arriving on a tagged interface is still a scan.
func TestParseEthernetVLAN(t *testing.T) {
	inner := ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(40000, 80, TCPSyn, 5))

	for _, tc := range []struct {
		name  string
		vlans []uint16
		want  error
	}{
		{"untagged", nil, nil},
		{"one 802.1Q tag", []uint16{100}, nil},
		{"QinQ, two tags", []uint16{100, 200}, nil},
		// Beyond the bound the parser stops unwrapping; the ethertype it is
		// left holding is the VLAN one, so the frame is reported as not IP
		// rather than parsed at a wrong offset.
		{"three tags, past the bound", []uint16{100, 200, 300}, ErrNotIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p Probe
			err := ParseEthernet(ethFrame(ethTypeIPv4, tc.vlans, inner), &p)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil && p.DstPort != 80 {
				t.Fatalf("DstPort = %d, want 80", p.DstPort)
			}
		})
	}
}

func TestParseEthernetRejects(t *testing.T) {
	var p Probe
	if err := ParseEthernet(make([]byte, 13), &p); !errors.Is(err, ErrTooShort) {
		t.Fatalf("a 13-byte frame: err = %v, want ErrTooShort", err)
	}
	// ARP is not an error in the world, just not ours.
	if err := ParseEthernet(ethFrame(0x0806, nil, make([]byte, 28)), &p); !errors.Is(err, ErrNotIP) {
		t.Fatalf("ARP: err = %v, want ErrNotIP", err)
	}
	// A VLAN tag the frame is too short to hold.
	short := append(dstMACBytes[:], srcMACBytes[:]...)
	short = append(short, be16(ethTypeVLAN)...)
	if err := ParseEthernet(short, &p); !errors.Is(err, ErrTooShort) {
		t.Fatalf("truncated VLAN tag: err = %v, want ErrTooShort", err)
	}
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

func TestParseIPv4Rejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  []byte
		want error
	}{
		{"empty", nil, ErrTooShort},
		{"shorter than the minimum header", append([]byte{4<<4 | 5}, make([]byte, 18)...), ErrTooShort},
		{"version 5", append([]byte{5 << 4}, make([]byte, 40)...), ErrNotIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p Probe
			if err := ParseIP(tc.pkt, &p); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestParseIPv4RejectsImpossibleIHL: an IHL smaller than the header it
// describes would make the transport offset point inside the IP header itself.
// flowhawk computes the L4 offset from IHL without ever checking it.
func TestParseIPv4RejectsImpossibleIHL(t *testing.T) {
	pkt := ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(1, 2, TCPSyn, 5))

	tooSmall := append([]byte(nil), pkt...)
	tooSmall[0] = 4<<4 | 4 // IHL 4 words = 16 bytes, less than the 20-byte minimum
	var p Probe
	if err := ParseIP(tooSmall, &p); !errors.Is(err, ErrTooShort) {
		t.Fatalf("IHL 4: err = %v, want ErrTooShort", err)
	}
	if p.Anomalies&AnomalyTruncated == 0 {
		t.Fatalf("a malformed IHL must be recorded as truncated")
	}

	// An IHL claiming more header than arrived is a different case, and must NOT
	// discard the probe. If the check ran before the addresses were read,
	// p.Src would stay invalid and AFPacketSource.readLoop would drop the
	// packet outright. Setting IHL to 15 on a short frame would then be a
	// complete evasion of that path -- no score, no anomaly, no trace -- while
	// the eBPF path, which recovers the addresses first, counted it. The
	// kernel/Go differential catches exactly this kind of split.
	tooBig := append([]byte(nil), pkt...)
	tooBig[0] = 4<<4 | 15 // 60 bytes of header in a 40-byte packet
	p = Probe{}
	if err := ParseIP(tooBig, &p); !errors.Is(err, ErrNoTransport) {
		t.Fatalf("IHL 15: err = %v, want ErrNoTransport", err)
	}
	if p.Src != v4src || p.Dst != v4dst {
		t.Fatalf("IHL 15: src/dst = %v/%v, want %v/%v; the addresses are in the first"+
			" 20 bytes and dropping them is what made this an evasion", p.Src, p.Dst, v4src, v4dst)
	}
	if p.Anomalies&AnomalyTruncated == 0 {
		t.Fatal("IHL 15: the unreachable transport header must be recorded as truncated")
	}
	if p.TCPFlagsValid {
		t.Fatal("IHL 15: no transport header was read, so no flags may be reported")
	}
}

// TestParseIPv4NonInitialFragment: past the first fragment there is no
// transport header at any offset. Reading on would interpret payload bytes as
// ports and flags -- which is how a fragmented scan gets reported as a NULL
// scan by tools that guess.
func TestParseIPv4NonInitialFragment(t *testing.T) {
	pkt := ipv4Packet(ProtoTCP, v4src, v4dst, 185, false, make([]byte, 20))

	var p Probe
	err := ParseIP(pkt, &p)
	if !errors.Is(err, ErrNoTransport) {
		t.Fatalf("err = %v, want ErrNoTransport", err)
	}
	if p.Anomalies&AnomalyFragment == 0 {
		t.Fatalf("a non-initial fragment must be recorded as such")
	}
	if p.Src != v4src || p.Proto != ProtoTCP {
		t.Fatalf("the addresses and protocol must still be recovered, got %s proto %d", p.Src, p.Proto)
	}
	if p.DstPort != 0 || p.TCPFlagsValid {
		t.Fatalf("nothing may be claimed about ports or flags, got port %d flags valid=%v",
			p.DstPort, p.TCPFlagsValid)
	}
}

// TestParseIPv4FirstFragmentOfNmapDashF is the shape nmap -f actually puts on
// the wire: fragment offset 0, More Fragments set, and only the first eight
// bytes of the TCP header.
//
// The ports are genuinely present. Dropping the packet is what makes the scan
// invisible; reading the flag octet that is not there is what makes it look
// like a NULL scan. Both are wrong, and this pins the third answer.
func TestParseIPv4FirstFragmentOfNmapDashF(t *testing.T) {
	pkt := ipv4Packet(ProtoTCP, v4src, v4dst, 0, true, tcpHeader(40000, 443, TCPSyn, 5)[:8])

	var p Probe
	if err := ParseIP(pkt, &p); err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.SrcPort != 40000 || p.DstPort != 443 {
		t.Fatalf("ports = %d -> %d, want 40000 -> 443", p.SrcPort, p.DstPort)
	}
	if p.TCPFlagsValid {
		t.Fatalf("the flag octet was not in the fragment; it must not be claimed as read")
	}
	if p.TCPFlags != 0 {
		t.Fatalf("TCPFlags = %#x, want 0 alongside TCPFlagsValid=false", p.TCPFlags)
	}
	if p.Anomalies&AnomalyTruncated == 0 {
		t.Fatalf("the truncation must be recorded")
	}
	if p.Anomalies&AnomalyFragment != 0 {
		t.Fatalf("the first fragment is readable; it is not a non-initial fragment")
	}
}

func TestParseIPv4UDPAndOtherProtocols(t *testing.T) {
	var p Probe
	if err := ParseIP(ipv4Packet(ProtoUDP, v4src, v4dst, 0, false, udpHeader(53, 5353)), &p); err != nil {
		t.Fatalf("UDP: %v", err)
	}
	if p.SrcPort != 53 || p.DstPort != 5353 {
		t.Fatalf("UDP ports = %d -> %d", p.SrcPort, p.DstPort)
	}

	// ICMP has no ports, but it does have a message type, and that is read: the
	// engine scores an ICMP source once per distinct type, which is what makes
	// scoring it safe at all. See Probe.ICMPType.
	p = Probe{}
	icmp := []byte{icmpv4Timestamp, 0, 0, 0, 0, 0, 0, 0}
	if err := ParseIP(ipv4Packet(ProtoICMP, v4src, v4dst, 0, false, icmp), &p); err != nil {
		t.Fatalf("ICMP: %v", err)
	}
	if p.Proto != ProtoICMP || p.Src != v4src {
		t.Fatalf("a port-less protocol must still yield its number and addresses, got proto %d", p.Proto)
	}
	if p.ICMPType() != icmpv4Timestamp || p.ICMPCode() != 0 {
		t.Fatalf("ICMP type/code = %d/%d, want %d/0", p.ICMPType(), p.ICMPCode(), icmpv4Timestamp)
	}

	// An IP protocol scan is a stream of exactly these.
	p = Probe{}
	if err := ParseIP(ipv4Packet(47, v4src, v4dst, 0, false, nil), &p); !errors.Is(err, ErrNoTransport) {
		t.Fatalf("GRE: err = %v, want ErrNoTransport", err)
	}
	if p.Proto != 47 {
		t.Fatalf("Proto = %d, want 47", p.Proto)
	}
}

func TestParseTransportTruncation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		proto      uint8
		payload    []byte
		wantErr    error
		wantPorts  bool
		wantAnomal Anomaly
	}{
		{"TCP with 3 bytes", ProtoTCP, make([]byte, 3), ErrTooShort, false, AnomalyTruncated},
		{"TCP with 8 bytes", ProtoTCP, tcpHeader(1, 2, TCPSyn, 5)[:8], nil, true, AnomalyTruncated},
		{"TCP with 14 bytes", ProtoTCP, tcpHeader(1, 2, TCPFin, 5)[:14], nil, true, AnomalyTruncated},
		{"UDP with 7 bytes", ProtoUDP, make([]byte, 7), ErrTooShort, false, AnomalyTruncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p Probe
			err := ParseIP(ipv4Packet(tc.proto, v4src, v4dst, 0, false, tc.payload), &p)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantPorts && (p.SrcPort != 1 || p.DstPort != 2) {
				t.Fatalf("ports = %d -> %d, want 1 -> 2", p.SrcPort, p.DstPort)
			}
			if p.Anomalies&tc.wantAnomal == 0 {
				t.Fatalf("anomalies = %#x, want %#x set", p.Anomalies, tc.wantAnomal)
			}
		})
	}

	// A 14-byte TCP header does contain the flag octet, so it may be claimed.
	var p Probe
	_ = ParseIP(ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(1, 2, TCPFin, 5)[:14]), &p)
	if !p.TCPFlagsValid || p.TCPFlags != TCPFin {
		t.Fatalf("flags = %#x (valid=%v), want FIN read", p.TCPFlags, p.TCPFlagsValid)
	}
}

// TestParseTCPDataOffset covers the option-length field: a SYN with no options
// is the masscan signature, and an offset pointing past the packet is malformed.
func TestParseTCPDataOffset(t *testing.T) {
	var p Probe
	if err := ParseIP(ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(1, 2, TCPSyn, 5)), &p); err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.Anomalies&AnomalyNoTCPOptions == 0 {
		t.Fatalf("a SYN with a 20-byte header carries no options; that must be recorded")
	}

	p = Probe{}
	if err := ParseIP(ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(1, 2, TCPSyn, 8)), &p); err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.Anomalies&AnomalyNoTCPOptions != 0 {
		t.Fatalf("a SYN with 12 bytes of options must not be flagged")
	}

	// A FIN scan packet has no options either, but only a SYN is expected to
	// carry them, so it must not be flagged.
	p = Probe{}
	if err := ParseIP(ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(1, 2, TCPFin, 5)), &p); err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.Anomalies&AnomalyNoTCPOptions != 0 {
		t.Fatalf("only a SYN is expected to advertise options")
	}

	// Data offset claiming more header than the packet holds.
	bad := tcpHeader(1, 2, TCPSyn, 5)
	bad[12] = 15 << 4
	p = Probe{}
	if err := ParseIP(ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, bad), &p); err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.Anomalies&AnomalyTruncated == 0 {
		t.Fatalf("a data offset past the end of the packet must be recorded")
	}
	if p.DstPort != 2 {
		t.Fatalf("the ports were readable and must still be reported, got %d", p.DstPort)
	}
}

// ---------------------------------------------------------------------------
// IPv6 and its three extension-header length conventions
// ---------------------------------------------------------------------------

func TestParseIPv6Plain(t *testing.T) {
	pkt := ipv6Packet(ProtoTCP, v6src, v6dst, tcpHeader(40000, 22, TCPSyn, 5))

	var p Probe
	if err := ParseIP(pkt, &p); err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.Src != v6src || p.Dst != v6dst {
		t.Fatalf("addresses = %s -> %s", p.Src, p.Dst)
	}
	if p.Proto != ProtoTCP || p.DstPort != 22 {
		t.Fatalf("proto %d port %d", p.Proto, p.DstPort)
	}
}

// TestParseIPv6RefusesV4MappedAddresses: an IPv4-mapped address in a genuine
// IPv6 packet is refused on either side of the header, and nothing is reported.
//
// This is not pedantry about RFC 4291 section 2.5.5.2. Linux drops such a packet
// in ip6_rcv, so it probes nothing -- but TC ingress runs before ip6_rcv, and
// parsers that kept the record would disagree about whose address it was: the
// eBPF path would unmap it and report 10.77.0.9, the AF_PACKET path would
// report ::ffff:10.77.0.9. The eBPF reading is the dangerous one. An on-link
// sender with no ability to spoof IPv4 could send IPv6 packets carrying a
// v4-mapped source of their choosing, touch a few dozen ports, and have the
// daemon install an nftables rule against that IPv4 address: a
// remote-triggered block of an arbitrary third party. The kernel/Go
// differential catches exactly this kind of split.
func TestParseIPv6RefusesV4MappedAddresses(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:10.77.0.9")

	for _, tc := range []struct {
		name     string
		src, dst netip.Addr
	}{
		{"source", mapped, v6dst},
		{"destination", v6src, mapped},
		{"both", mapped, mapped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := ipv6Packet(ProtoTCP, tc.src, tc.dst, tcpHeader(40000, 22, TCPSyn, 5))
			var p Probe
			if err := ParseIP(pkt, &p); !errors.Is(err, ErrNotIP) {
				t.Fatalf("err = %v, want ErrNotIP", err)
			}
			// AFPacketSource.readLoop drops a probe with no source address, and
			// that is the mechanism by which this one goes no further.
			if p.Src.IsValid() {
				t.Fatalf("src = %s; a refused packet must leave nothing behind for"+
					" the engine to score or the blocker to act on", p.Src)
			}
		})
	}
}

func TestParseIPv6TooShort(t *testing.T) {
	var p Probe
	if err := ParseIP(append([]byte{6 << 4}, make([]byte, 38)...), &p); !errors.Is(err, ErrTooShort) {
		t.Fatalf("err = %v, want ErrTooShort", err)
	}
	if p.Anomalies&AnomalyTruncated == 0 {
		t.Fatalf("truncation must be recorded")
	}
}

// TestExtHeaderLenConventions checks the arithmetic on its own, against the
// three specifications it implements.
func TestExtHeaderLenConventions(t *testing.T) {
	for _, tc := range []struct {
		name      string
		nh        uint8
		hdrExtLen uint8
		want      int
		spec      string
	}{
		{"hop-by-hop, minimum", ipv6ExtHopByHop, 0, 8, "RFC 8200 4.3: (len+1)*8, len=0 is a valid 8-byte header"},
		{"hop-by-hop, one extra unit", ipv6ExtHopByHop, 1, 16, "RFC 8200 4.3"},
		{"destination options", ipv6ExtDestOpts, 3, 32, "RFC 8200 4.6"},
		{"routing", ipv6ExtRouting, 2, 24, "RFC 8200 4.4"},
		{"fragment ignores the field", ipv6ExtFragment, 0xff, 8, "RFC 8200 4.5: fixed 8 octets, second byte reserved"},
		{"AH, minimum", ipv6ExtAH, 4, 24, "RFC 4302 2.2: (len+2)*4"},
		{"AH, longer ICV", ipv6ExtAH, 7, 36, "RFC 4302 2.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := extHeaderLen(tc.nh, tc.hdrExtLen); got != tc.want {
				t.Fatalf("extHeaderLen(%d, %d) = %d, want %d (%s)",
					tc.nh, tc.hdrExtLen, got, tc.want, tc.spec)
			}
		})
	}
}

// TestParseIPv6ZeroLengthExtensionHeaderIsValid is PortSentry's first IPv6 bug
// made into a regression test: it rejects the packet when Hdr Ext Len is zero
// ("IPv6 extension header length is 0, ignoring packet"), which discards
// perfectly legitimate 8-byte hop-by-hop headers.
func TestParseIPv6ZeroLengthExtensionHeaderIsValid(t *testing.T) {
	// A SYN carrying options, so the only anomaly that could show up is one the
	// extension header caused.
	payload := append(extHeader(ProtoTCP, 8), tcpHeader(40000, 80, TCPSyn, 8)...)
	pkt := ipv6Packet(ipv6ExtHopByHop, v6src, v6dst, payload)

	var p Probe
	if err := ParseIP(pkt, &p); err != nil {
		t.Fatalf("an 8-byte hop-by-hop header must be skipped, got %v", err)
	}
	if p.Proto != ProtoTCP || p.DstPort != 80 {
		t.Fatalf("proto %d port %d, want TCP 80", p.Proto, p.DstPort)
	}
	if p.Anomalies != 0 {
		t.Fatalf("ordinary traffic must raise no anomaly, got %#x", p.Anomalies)
	}
}

// TestParseIPv6AuthenticationHeaderLength is PortSentry's second IPv6 bug: it
// applies the 8-octet rule to the Authentication Header, which measures in
// 4-octet units minus 2, and so lands on the wrong offset.
//
// The assertion is on the port numbers: with the wrong convention the parser
// reads 16 bytes further into the packet and the ports do not match.
func TestParseIPv6AuthenticationHeaderLength(t *testing.T) {
	const ahLen = 24 // Payload Len = 4, the common case for HMAC-SHA1-96
	payload := append(ahHeader(ProtoTCP, ahLen), tcpHeader(40000, 8080, TCPSyn, 5)...)
	pkt := ipv6Packet(ipv6ExtAH, v6src, v6dst, payload)

	var p Probe
	if err := ParseIP(pkt, &p); err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.Proto != ProtoTCP {
		t.Fatalf("Proto = %d, want TCP", p.Proto)
	}
	if p.SrcPort != 40000 || p.DstPort != 8080 {
		t.Fatalf("ports = %d -> %d, want 40000 -> 8080: the AH length convention is wrong",
			p.SrcPort, p.DstPort)
	}
}

func TestParseIPv6HeaderChain(t *testing.T) {
	// hop-by-hop -> routing -> destination options -> TCP
	payload := extHeader(ipv6ExtRouting, 8)
	payload = append(payload, extHeader(ipv6ExtDestOpts, 24)...)
	payload = append(payload, extHeader(ProtoTCP, 16)...)
	payload = append(payload, tcpHeader(40000, 445, TCPSyn|TCPFin, 5)...)
	pkt := ipv6Packet(ipv6ExtHopByHop, v6src, v6dst, payload)

	var p Probe
	if err := ParseIP(pkt, &p); err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.DstPort != 445 || p.TCPFlags != TCPSyn|TCPFin {
		t.Fatalf("port %d flags %#x, want 445 and SYN|FIN", p.DstPort, p.TCPFlags)
	}
}

// TestParseIPv6ChainBoundIsReportedNotSwallowed: Topera hides the TCP header
// behind seven or more empty extension headers precisely so that analysers give
// up quietly. Giving up is unavoidable -- an eBPF program cannot loop without a
// bound -- but doing it quietly is not.
func TestParseIPv6ChainBoundIsReportedNotSwallowed(t *testing.T) {
	var payload []byte
	for i := 0; i < maxExtHeaders+1; i++ {
		payload = append(payload, extHeader(ipv6ExtDestOpts, 8)...)
	}
	payload = append(payload, tcpHeader(40000, 22, TCPSyn, 5)...)
	pkt := ipv6Packet(ipv6ExtDestOpts, v6src, v6dst, payload)

	var p Probe
	err := ParseIP(pkt, &p)
	if !errors.Is(err, ErrNoTransport) {
		t.Fatalf("err = %v, want ErrNoTransport", err)
	}
	if p.Anomalies&AnomalyExtHeaderChain == 0 {
		t.Fatalf("an over-long chain must be reported as an evasion sign")
	}
	if p.Src != v6src {
		t.Fatalf("the source must still be recovered, got %s", p.Src)
	}

	// Exactly at the bound the packet is still parsed.
	payload = nil
	for i := 0; i < maxExtHeaders-1; i++ {
		payload = append(payload, extHeader(ipv6ExtDestOpts, 8)...)
	}
	payload = append(payload, extHeader(ProtoTCP, 8)...)
	payload = append(payload, tcpHeader(40000, 22, TCPSyn, 5)...)
	p = Probe{}
	if err := ParseIP(ipv6Packet(ipv6ExtDestOpts, v6src, v6dst, payload), &p); err != nil {
		t.Fatalf("a chain of exactly %d headers must still parse, got %v", maxExtHeaders, err)
	}
	if p.DstPort != 22 {
		t.Fatalf("DstPort = %d, want 22", p.DstPort)
	}
}

func TestParseIPv6Fragment(t *testing.T) {
	// A first fragment carries the transport header and must be read.
	payload := append(fragHeader(ProtoTCP, 0, true), tcpHeader(40000, 139, TCPSyn, 5)...)
	var p Probe
	if err := ParseIP(ipv6Packet(ipv6ExtFragment, v6src, v6dst, payload), &p); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	if p.DstPort != 139 {
		t.Fatalf("DstPort = %d, want 139", p.DstPort)
	}

	// A later fragment has none.
	payload = append(fragHeader(ProtoTCP, 185, false), make([]byte, 20)...)
	p = Probe{}
	err := ParseIP(ipv6Packet(ipv6ExtFragment, v6src, v6dst, payload), &p)
	if !errors.Is(err, ErrNoTransport) {
		t.Fatalf("later fragment: err = %v, want ErrNoTransport", err)
	}
	if p.Anomalies&AnomalyFragment == 0 {
		t.Fatalf("a non-initial fragment must be recorded as such")
	}
	if p.Proto != ProtoTCP {
		t.Fatalf("Proto = %d, want the fragmented protocol (TCP)", p.Proto)
	}
	if p.DstPort != 0 {
		t.Fatalf("no port may be claimed from a later fragment, got %d", p.DstPort)
	}
}

// TestParseIPv6ESPIsNotWalked: everything after an ESP header is encrypted.
// Treating it as skippable would mean parsing ciphertext as a TCP header, and
// reporting whatever bytes happened to be there as ports and flags.
func TestParseIPv6ESPIsNotWalked(t *testing.T) {
	payload := append(make([]byte, 8), tcpHeader(40000, 22, TCPSyn, 5)...)
	var p Probe
	err := ParseIP(ipv6Packet(ipv6ExtESP, v6src, v6dst, payload), &p)
	if !errors.Is(err, ErrNoTransport) {
		t.Fatalf("err = %v, want ErrNoTransport", err)
	}
	if p.Proto != ipv6ExtESP {
		t.Fatalf("Proto = %d, want %d (ESP)", p.Proto, ipv6ExtESP)
	}
	if p.DstPort != 0 || p.TCPFlagsValid {
		t.Fatalf("nothing may be read out of an encrypted payload")
	}
}

func TestParseIPv6NoNextHeader(t *testing.T) {
	var p Probe
	err := ParseIP(ipv6Packet(ipv6NoNextHeader, v6src, v6dst, nil), &p)
	if !errors.Is(err, ErrNoTransport) {
		t.Fatalf("err = %v, want ErrNoTransport", err)
	}
	if p.Src != v6src {
		t.Fatalf("the addresses must still be recovered")
	}
}

func TestParseIPv6TruncatedExtensionHeader(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"one byte of an extension header", []byte{ProtoTCP}},
		{"a header claiming more than the packet holds", extHeader(ProtoTCP, 8)[:8:8]},
		{"a fragment header cut after two bytes", []byte{ProtoTCP, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nh := uint8(ipv6ExtDestOpts)
			payload := tc.payload
			if tc.name == "a fragment header cut after two bytes" {
				nh = ipv6ExtFragment
			}
			if tc.name == "a header claiming more than the packet holds" {
				payload = append([]byte(nil), tc.payload...)
				payload[1] = 4 // claims 40 bytes, only 8 present
			}
			var p Probe
			err := ParseIP(ipv6Packet(nh, v6src, v6dst, payload), &p)
			if !errors.Is(err, ErrTooShort) {
				t.Fatalf("err = %v, want ErrTooShort", err)
			}
			if p.Anomalies&AnomalyTruncated == 0 {
				t.Fatalf("truncation must be recorded")
			}
		})
	}
}

func TestParseIPv6UDP(t *testing.T) {
	var p Probe
	if err := ParseIP(ipv6Packet(ProtoUDP, v6src, v6dst, udpHeader(546, 547)), &p); err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.Proto != ProtoUDP || p.SrcPort != 546 || p.DstPort != 547 {
		t.Fatalf("proto %d ports %d -> %d", p.Proto, p.SrcPort, p.DstPort)
	}
}

func TestParseEthernetIPv6(t *testing.T) {
	frame := ethFrame(ethTypeIPv6, nil,
		ipv6Packet(ProtoTCP, v6src, v6dst, tcpHeader(40000, 3389, TCPFin|TCPPsh|TCPUrg, 5)))

	var p Probe
	if err := ParseEthernet(frame, &p); err != nil {
		t.Fatalf("ParseEthernet: %v", err)
	}
	if p.SrcMAC != srcMACBytes {
		t.Fatalf("the MAC must be recovered for IPv6 too")
	}
	if p.DstPort != 3389 || p.TCPFlags != TCPFin|TCPPsh|TCPUrg {
		t.Fatalf("port %d flags %#x, want 3389 and an Xmas combination", p.DstPort, p.TCPFlags)
	}
}

// TestParseNeverPanicsOnArbitraryInput feeds every truncation of a set of
// well-formed frames, plus a byte-flipped variant of each, and requires the
// parser to return rather than fault.
//
// The packet path runs on attacker-controlled input; a panic there is a remote
// denial of service on the daemon.
func TestParseNeverPanicsOnArbitraryInput(t *testing.T) {
	seeds := [][]byte{
		ethFrame(ethTypeIPv4, nil, ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(1, 2, TCPSyn, 8))),
		ethFrame(ethTypeIPv4, []uint16{100, 200}, ipv4Packet(ProtoUDP, v4src, v4dst, 0, false, udpHeader(1, 2))),
		ethFrame(ethTypeIPv6, nil, ipv6Packet(ProtoTCP, v6src, v6dst, tcpHeader(1, 2, TCPFin, 5))),
		ethFrame(ethTypeIPv6, nil, ipv6Packet(ipv6ExtHopByHop, v6src, v6dst,
			append(extHeader(ipv6ExtAH, 16), append(ahHeader(ProtoTCP, 24), tcpHeader(1, 2, TCPSyn, 5)...)...))),
		ethFrame(ethTypeIPv6, nil, ipv6Packet(ipv6ExtFragment, v6src, v6dst,
			append(fragHeader(ProtoTCP, 0, true), tcpHeader(1, 2, TCPSyn, 5)...))),
	}

	for si, seed := range seeds {
		for n := 0; n <= len(seed); n++ {
			var p Probe
			_ = ParseEthernet(seed[:n], &p)

			// And with each byte of the prefix flipped in turn, so that length
			// fields, next-header values and version nibbles all take values the
			// builder would never produce.
			for i := 0; i < n; i++ {
				mutated := append([]byte(nil), seed[:n]...)
				mutated[i] ^= 0xff
				var q Probe
				_ = ParseEthernet(mutated, &q)
			}
		}
		_ = si
	}
}

// ---------------------------------------------------------------------------
// bounding the payload by what the IP header declares
//
// A parser that hands
// the whole frame remainder to the transport layer reads bytes that are not
// part of the datagram -- and on a short probe there are always such bytes,
// because Ethernet pads every frame to 60 octets and every router regenerates
// that padding.
// ---------------------------------------------------------------------------

// padTo60 appends zero bytes the way a network interface does.
func padTo60(frame []byte) []byte {
	for len(frame) < 60 {
		frame = append(frame, 0)
	}
	return frame
}

// TestEthernetPaddingIsNotReadAsTCPFlags is the headline case.
//
// nmap -f emits a 28-byte datagram: 20 bytes of IP and the first 8 bytes of the
// TCP header. The frame is 42 bytes and arrives padded to 60. Reading the 14th
// byte of the transport slice then lands in the padding, yields 0x00, and gets
// reported as a NULL scan -- a technique that was never on the wire. That is
// exactly the failure TCPFlagsValid exists to prevent, and it was reachable by
// any remote sender.
func TestEthernetPaddingIsNotReadAsTCPFlags(t *testing.T) {
	inner := ipv4Packet(ProtoTCP, v4src, v4dst, 0, true, tcpHeader(40000, 22, TCPSyn, 5)[:8])
	if len(inner) != 28 {
		t.Fatalf("the datagram is %d bytes, want 28", len(inner))
	}
	frame := padTo60(ethFrame(ethTypeIPv4, nil, inner))
	if len(frame) != 60 {
		t.Fatalf("the frame is %d bytes, want 60", len(frame))
	}

	var p Probe
	if err := ParseEthernet(frame, &p); err != nil {
		t.Fatalf("ParseEthernet: %v", err)
	}
	if p.TCPFlagsValid {
		t.Fatalf("the flag octet was in the padding, not in the datagram; it must not be claimed as read")
	}
	if p.TCPFlags != 0 {
		t.Fatalf("TCPFlags = %#x, want 0 alongside TCPFlagsValid=false", p.TCPFlags)
	}
	if p.SrcPort != 40000 || p.DstPort != 22 {
		t.Fatalf("ports = %d -> %d, want 40000 -> 22: they ARE in the datagram", p.SrcPort, p.DstPort)
	}
	if p.Anomalies&AnomalyTrailer == 0 {
		t.Fatalf("the trailing padding must be recorded, got %#x", p.Anomalies)
	}
	if p.Anomalies&AnomalyFirstFragment == 0 {
		t.Fatalf("More Fragments was set; the split must be recorded, got %#x", p.Anomalies)
	}
}

// TestAttackerChosenTrailerCannotForgeFlags: an on-link sender controls every
// byte after the declared payload. None of them may become evidence.
func TestAttackerChosenTrailerCannotForgeFlags(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(trailer []byte) []byte
	}{
		{"ipv4", func(trailer []byte) []byte {
			pkt := ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(40000, 22, TCPSyn, 5)[:8])
			return ethFrame(ethTypeIPv4, nil, append(pkt, trailer...))
		}},
		{"ipv6", func(trailer []byte) []byte {
			pkt := ipv6Packet(ProtoTCP, v6src, v6dst, tcpHeader(40000, 22, TCPSyn, 5)[:8])
			return ethFrame(ethTypeIPv6, nil, append(pkt, trailer...))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A trailer placing Xmas flags exactly where a 20-byte TCP header
			// would carry them, and a plausible data offset beside it.
			trailer := make([]byte, 24)
			trailer[12-8] = 5 << 4
			trailer[13-8] = flagsXmas

			var p Probe
			if err := ParseEthernet(tc.build(trailer), &p); err != nil {
				t.Fatalf("ParseEthernet: %v", err)
			}
			if p.TCPFlagsValid {
				t.Fatalf("flags were taken from the trailer: the sender would choose the verdict")
			}
			if p.TCPFlags == flagsXmas {
				t.Fatalf("TCPFlags = %#x, the attacker's value", p.TCPFlags)
			}
			if p.Anomalies&AnomalyTrailer == 0 {
				t.Fatalf("the trailer must be recorded, got %#x", p.Anomalies)
			}
			if p.DstPort != 22 {
				t.Fatalf("DstPort = %d, want 22", p.DstPort)
			}
		})
	}
}

// TestDeclaredLengthShorterThanHeaderIsRefused: a length field describing less
// than the header it belongs to is malformed, and trusting it would produce a
// negative slice bound.
func TestDeclaredLengthShorterThanHeaderIsRefused(t *testing.T) {
	pkt := ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(1, 2, TCPSyn, 5))
	binary.BigEndian.PutUint16(pkt[2:4], 8) // total length 8, header is 20

	var p Probe
	if err := ParseIP(pkt, &p); !errors.Is(err, ErrTooShort) {
		t.Fatalf("err = %v, want ErrTooShort", err)
	}
	if p.Anomalies&AnomalyTruncated == 0 {
		t.Fatalf("the malformed length must be recorded")
	}
	if p.DstPort != 0 || p.TCPFlagsValid {
		t.Fatalf("nothing may be read out of a packet whose length field is impossible")
	}
}

// TestDeclaredLengthLongerThanCaptureIsTruncation: the opposite case is an
// honest snaplen cut, and what was captured is still usable.
func TestDeclaredLengthLongerThanCaptureIsTruncation(t *testing.T) {
	pkt := ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(40000, 443, TCPSyn, 5))
	binary.BigEndian.PutUint16(pkt[2:4], 1500) // claims far more than we hold

	var p Probe
	if err := ParseIP(pkt, &p); err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.Anomalies&AnomalyTruncated == 0 {
		t.Fatalf("a capture shorter than the declared datagram must be recorded as truncated")
	}
	if p.DstPort != 443 {
		t.Fatalf("DstPort = %d, want 443: the captured bytes are still real", p.DstPort)
	}
}

// TestIPv6PayloadLengthBoundsTheExtensionWalk: the same bound must apply before
// the extension chain is walked, or a trailer becomes a forged chain.
func TestIPv6PayloadLengthBoundsTheExtensionWalk(t *testing.T) {
	payload := append(extHeader(ProtoTCP, 8), tcpHeader(40000, 80, TCPSyn, 8)...)
	pkt := ipv6Packet(ipv6ExtHopByHop, v6src, v6dst, payload)
	// Declare only the extension header, then append a forged TCP header.
	binary.BigEndian.PutUint16(pkt[4:6], 8)

	var p Probe
	err := ParseIP(pkt, &p)
	if p.DstPort == 80 {
		t.Fatalf("the parser read past the declared payload (err=%v)", err)
	}
	if p.Anomalies&AnomalyTrailer == 0 {
		t.Fatalf("the bytes past the declared payload must be recorded, got %#x", p.Anomalies)
	}
}

// TestTripleVLANIsReportedNotSilentlyDropped: the unwrap is bounded, which is
// unavoidable, but a frame that exceeds the bound must leave a trace. Silently
// returning "not an IP packet" is what VLAN hopping counts on.
func TestTripleVLANIsReportedNotSilentlyDropped(t *testing.T) {
	inner := ipv4Packet(ProtoTCP, v4src, v4dst, 0, false, tcpHeader(40000, 22, TCPSyn, 8))

	var p Probe
	err := ParseEthernet(ethFrame(ethTypeIPv4, []uint16{100, 200, 300}, inner), &p)
	if !errors.Is(err, ErrNotIP) {
		t.Fatalf("err = %v, want ErrNotIP", err)
	}
	if p.Anomalies&AnomalyVLANDepth == 0 {
		t.Fatalf("a stack deeper than the bound must be recorded, got %#x", p.Anomalies)
	}

	// Two tags stay within the bound and must NOT raise it.
	p = Probe{}
	if err := ParseEthernet(ethFrame(ethTypeIPv4, []uint16{100, 200}, inner), &p); err != nil {
		t.Fatalf("two tags: %v", err)
	}
	if p.Anomalies&AnomalyVLANDepth != 0 {
		t.Fatalf("two tags are within the bound; no anomaly is owed")
	}
}

// TestEveryAcceptedExtensionChainFitsTheSnapLength: the AF_PACKET source keeps
// the first afPacketSnapLen bytes of a frame, the eBPF program reads all of it.
// For the two to agree, whatever the parser accepts must fit: a chain whose
// end ran past the bound put the TCP header beyond the snap length, and the
// fallback path read a truncated packet with no port where the kernel read a
// SYN. Each chain is parsed whole and cut to the snap length, and the two
// results must be the same.
func TestEveryAcceptedExtensionChainFitsTheSnapLength(t *testing.T) {
	syn := []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0xf0, TCPSyn, 0x72, 0x10, 0, 0, 0, 0}
	syn = append(syn, make([]byte, 40)...) // a 60-byte TCP header, the largest there is
	for _, shape := range []struct{ n, extLen int }{{1, 255}, {1, 127}, {8, 15}, {8, 16}, {4, 31}, {2, 63}, {7, 17}} {
		var chain []byte
		for i := 0; i < shape.n; i++ {
			h := make([]byte, (shape.extLen+1)*8)
			h[0] = 60
			if i == shape.n-1 {
				h[0] = ProtoTCP
			}
			h[1] = byte(shape.extLen)
			chain = append(chain, h...)
		}
		ip := make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(chain)+len(syn)))
		ip[6], ip[7] = 60, 64
		copy(ip[8:24], netip.MustParseAddr("2001:db8::9").AsSlice())
		copy(ip[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())
		frame := ethFrame(0x86dd, []uint16{1, 2}, append(append(ip, chain...), syn...))

		var whole, cut Probe
		errWhole := ParseEthernet(frame, &whole)
		if len(frame) > afPacketSnapLen {
			frame = frame[:afPacketSnapLen]
		}
		errCut := ParseEthernet(frame, &cut)
		// A frame that was actually cut is marked truncated, legitimately;
		// the verdict -- the port read, the chain refused or not -- must match.
		if (errWhole == nil) != (errCut == nil) || whole.DstPort != cut.DstPort ||
			whole.Anomalies&^AnomalyTruncated != cut.Anomalies&^AnomalyTruncated {
			t.Errorf("%d headers of %d bytes: whole frame gives port %d %v (err %v),"+
				" the first %d bytes give port %d %v (err %v)",
				shape.n, (shape.extLen+1)*8, whole.DstPort, AnomalyStrings(whole.Anomalies), errWhole,
				afPacketSnapLen, cut.DstPort, AnomalyStrings(cut.Anomalies), errCut)
		}
	}
}

// chainedSYN builds an IPv6 SYN to dport behind n Destination Options headers
// of extLen (in 8-octet units beyond the first 8).
func chainedSYN(src, dst netip.Addr, dport uint16, n, extLen int) []byte {
	syn := []byte{0x9c, 0x40, byte(dport >> 8), byte(dport), 0, 0, 0, 1, 0, 0, 0, 0, 0x50, TCPSyn, 0x72, 0x10, 0, 0, 0, 0}
	var chain []byte
	for i := 0; i < n; i++ {
		h := make([]byte, (extLen+1)*8)
		h[0] = 60
		if i == n-1 {
			h[0] = ProtoTCP
		}
		h[1] = byte(extLen)
		chain = append(chain, h...)
	}
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(chain)+len(syn)))
	ip[6], ip[7] = 60, 64
	copy(ip[8:24], src.AsSlice())
	copy(ip[24:40], dst.AsSlice())
	return ethFrame(0x86dd, nil, append(append(ip, chain...), syn...))
}

// TestAScanBehindAnExhaustedExtensionWalkIsReported: Linux answers a SYN behind
// any number of IPv6 extension headers, and both parsers walk a bounded number
// of them (8, and 1024 bytes). A packet that exhausts the walk carries no port
// the parser could read. If it scored nothing, nine empty Destination Options
// headers in front of every SYN, or one of 1112 bytes, would hide a complete
// IPv6 port scan -- measured on a real kernel, which answered every probe. Such
// a packet is never ordinary traffic, so it scores by itself, under a
// technique of its own. It is not evidence: its source is as forgeable as any.
func TestAScanBehindAnExhaustedExtensionWalkIsReported(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::9")
	for _, shape := range []struct {
		name      string
		n, extLen int
	}{
		{"nine empty headers", 9, 0},
		{"one 1112-byte header", 1, 138},
		{"one 2048-byte header", 1, 255},
	} {
		e := newTestEngine(t, testConfig(), newFakeHost())
		var ev *ScanEvent
		for port := 1; port <= 100 && ev == nil; port++ {
			var p Probe
			_ = ParseEthernet(chainedSYN(src, victim6, uint16(port), shape.n, shape.extLen), &p)
			if p.Anomalies&AnomalyExtHeaderChain == 0 {
				t.Fatalf("%s: the walk was not exhausted; the test does not exercise its case", shape.name)
			}
			p.TimeNs = sec + uint64(port)*ms
			ev = e.Process(&p)
		}
		if ev == nil {
			t.Errorf("%s: a hundred SYNs behind an exhausted extension walk were never reported", shape.name)
			continue
		}
		if ev.Method != MethodExtHeaderEvasion {
			t.Errorf("%s: reported as %v", shape.name, ev.Method)
		}
		if ev.BlockEligible {
			t.Errorf("%s: block-eligible on packets whose source nothing corroborates", shape.name)
		}
	}

	// And an ordinary chain is still an ordinary SYN.
	var p Probe
	_ = ParseEthernet(chainedSYN(src, victim6, 22, 8, 0), &p)
	if p.Anomalies&AnomalyExtHeaderChain != 0 || p.DstPort != 22 {
		t.Fatalf("eight headers are within the walk: got port %d, anomalies %v", p.DstPort, AnomalyStrings(p.Anomalies))
	}
}

// jumboTCP builds an IPv6 TCP segment in the shape Linux's BIG TCP GRO hands
// to tc ingress and to packet sockets, as RFC 2675 jumbograms have it: Payload
// Length 0, a Hop-by-Hop header with the Jumbo Payload option, then an
// ordinary, fully readable TCP header.
func jumboTCP(src, dst netip.Addr, sport, dport uint16, flags uint8) []byte {
	tcp := make([]byte, 20+64)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = 0x50
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 0x7210)
	hbh := []byte{ProtoTCP, 0, 0xC2, 4, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hbh[4:], uint32(len(hbh)+len(tcp)))
	ip := make([]byte, 40)
	ip[0] = 0x60
	ip[7] = 64
	copy(ip[8:24], src.AsSlice())
	copy(ip[24:40], dst.AsSlice())
	return ethFrame(0x86dd, nil, append(append(ip, hbh...), tcp...))
}

// TestABigTCPTransferIsNotAScan: with BIG TCP enabled (gso/gro_max_size above
// 64 KiB), Linux hands IPv6 segments over 64 KiB to tc and packet sockets in
// the jumbogram shape, which the parsers flag as an extension-header anomaly
// while reading the TCP header normally. The evasion rule fired on that flag
// alone, before the known-connection check: a download over a known
// connection was reported after nine segments, measured on a real 6.18
// capture, and one later SYN to a closed port made the server blockable. Only
// a walk that actually failed -- the transport not reached -- is evasion.
func TestABigTCPTransferIsNotAScan(t *testing.T) {
	server := netip.MustParseAddr("2001:db8::80")
	h := newFakeHost()
	e := newTestEngine(t, testConfig(), h)
	frame := jumboTCP(server, victim6, 443, 50000, TCPAck|TCPPsh)
	at := sec
	for i := 0; i < 7*60*10; i++ {
		var p Probe
		if err := ParseEthernet(frame, &p); err != nil || !p.IsTCP() {
			t.Fatalf("the jumbo segment did not parse as TCP (%v); the test does not exercise its case", err)
		}
		h.connections[connKey(&p)] = true
		at += 100 * ms
		p.TimeNs = at
		if ev := e.Process(&p); ev != nil {
			t.Fatalf("segment %d of a known connection's BIG TCP transfer was reported as %s", i+1, ev.Method)
		}
	}
	at += 10 * ms
	if ev := e.Process(synProbe(at, server, victim6, 8080)); ev != nil {
		t.Fatalf("one SYN to a closed port from a BIG TCP peer was reported (score %d, block-eligible %v)",
			ev.Score, ev.BlockEligible)
	}
}

// TestAScanInJumbogramsIsStillAScan: the jumbogram shape does not hide a
// scan. Its TCP header is read, so its SYNs are scored as SYNs.
func TestAScanInJumbogramsIsStillAScan(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::66")
	e := newTestEngine(t, testConfig(), newFakeHost())
	var ev *ScanEvent
	for port := 1; port <= 30 && ev == nil; port++ {
		var p Probe
		_ = ParseEthernet(jumboTCP(src, victim6, 40000, uint16(port), TCPSyn), &p)
		p.TimeNs = sec + uint64(port)*ms
		ev = e.Process(&p)
	}
	if ev == nil || ev.Method != MethodSYN {
		t.Fatalf("a SYN scan sent as jumbograms was reported as %v", ev)
	}
}

// TestExtensionEvasionFollowsTheDetectorSwitches: an evasion probe carries a
// TCP or UDP header the parser could not reach, so it counts whenever either
// detector is on, and not at all when both are off. Its technique reaches the
// GUI by name.
func TestExtensionEvasionFollowsTheDetectorSwitches(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::9")
	for _, c := range []struct {
		tcp, udp bool
		counted  bool
	}{
		{true, false, true},
		{false, true, true},
		{false, false, false},
	} {
		cfg := testConfig()
		cfg.DetectTCP, cfg.DetectUDP, cfg.DetectProtocolScan = c.tcp, c.udp, true
		e := newTestEngine(t, cfg, newFakeHost())
		var ev *ScanEvent
		for port := 1; port <= 30 && ev == nil; port++ {
			var p Probe
			_ = ParseEthernet(chainedSYN(src, victim6, uint16(port), 9, 0), &p)
			p.TimeNs = sec + uint64(port)*ms
			ev = e.Process(&p)
		}
		if got := ev != nil; got != c.counted {
			t.Errorf("DetectTCP=%v DetectUDP=%v: reported=%v, want %v", c.tcp, c.udp, got, c.counted)
		}
		if ev != nil && ev.Method.String() != "ipv6-extension-evasion" {
			t.Errorf("reported under the name %q", ev.Method.String())
		}
	}
}

// TestExtensionEvasionIsNamedAmongOtherTechniques: evasion probes are a
// family of their own when the technique is named. Beside as many SYNs,
// neither dominates and the scan is mixed; one of them among forty UDP
// probes leaves it a UDP scan (see oneFamilyDominates).
func TestExtensionEvasionIsNamedAmongOtherTechniques(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::9")
	evasion := func(e *Engine, n int, at *uint64) {
		for k := 0; k < n; k++ {
			var p Probe
			_ = ParseEthernet(chainedSYN(src, victim6, uint16(1000+k), 9, 0), &p)
			*at += ms
			p.TimeNs = *at
			e.Process(&p)
		}
	}
	method := func(e *Engine) ScanMethod {
		shard := e.table.shardFor(src)
		shard.mu.Lock()
		defer shard.mu.Unlock()
		st, _ := shard.lookup(src)
		return describeMethod(st)
	}

	e := newTestEngine(t, testConfig(), newFakeHost())
	at := sec
	for k := 0; k < 5; k++ {
		at += ms
		e.Process(synProbe(at, src, victim6, uint16(1+k)))
	}
	evasion(e, 5, &at)
	if m := method(e); m != MethodMixed {
		t.Errorf("five SYNs and five evasion probes are named %v, want %v", m, MethodMixed)
	}

	e = newTestEngine(t, testConfig(), newFakeHost())
	at = sec
	for k := 0; k < 40; k++ {
		at += ms
		e.Process(udpProbe(at, src, victim6, uint16(1+k)))
	}
	evasion(e, 1, &at)
	if m := method(e); m != MethodUDP {
		t.Errorf("forty UDP probes and one evasion probe are named %v, want %v", m, MethodUDP)
	}
}

// TestAJumboUDPDatagramIsNotEvasion: the jumbogram shape carries UDP as well,
// read like any other datagram; only a walk that stopped on an extension
// header is evasion, whatever the transport behind a successful one.
func TestAJumboUDPDatagramIsNotEvasion(t *testing.T) {
	server := netip.MustParseAddr("2001:db8::80")
	udp := make([]byte, 8+64)
	binary.BigEndian.PutUint16(udp[0:], 443)
	binary.BigEndian.PutUint16(udp[2:], 50000)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	hbh := []byte{ProtoUDP, 0, 0xC2, 4, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hbh[4:], uint32(len(hbh)+len(udp)))
	ip := make([]byte, 40)
	ip[0] = 0x60
	ip[7] = 64
	copy(ip[8:24], server.AsSlice())
	copy(ip[24:40], victim6.AsSlice())
	var p Probe
	if err := ParseEthernet(ethFrame(0x86dd, nil, append(append(ip, hbh...), udp...)), &p); err != nil || !p.IsUDP() {
		t.Fatalf("the jumbo datagram did not parse as UDP (%v); the test does not exercise its case", err)
	}
	e := newTestEngine(t, testConfig(), newFakeHost())
	if reason := e.classify(&p).reason; reason == "ipv6-extension-evasion" {
		t.Fatal("a readable jumbo UDP datagram was classed as extension-header evasion")
	}
}
