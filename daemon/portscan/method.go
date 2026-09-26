package portscan

import "fmt"

// ScanMethod names the technique a source appears to be using, derived from
// the two flag masks kept per source (flagsOr and flagsAnd, as scanlogd.c:52-53):
// the exact combination when it never varied, and the fact that it varied
// otherwise. A method is named only when the packets determine it; where two
// nmap options emit identical packets, the shared name is returned (MethodACK).
type ScanMethod uint8

// Scan methods.
const (
	// MethodUnknown means no method could be determined.
	MethodUnknown ScanMethod = iota
	// MethodSYN is a half-open or connect scan: nmap -sS or -sT. The two are
	// indistinguishable from the flags of the probe alone; they differ only in
	// whether the handshake is completed on open ports.
	MethodSYN
	// MethodFIN is nmap -sF.
	MethodFIN
	// MethodNULL is nmap -sN: a TCP header with no control bits set.
	MethodNULL
	// MethodXmas is nmap -sX: FIN, PSH and URG.
	MethodXmas
	// MethodMaimon is nmap -sM: FIN and ACK.
	MethodMaimon
	// MethodACK covers nmap -sA and nmap -sW. Both send a bare ACK; they
	// differ only in how the scanner interprets the window field of the RST it
	// receives back. Nothing in the packets reaching us distinguishes them, so
	// claiming one would be a fabrication.
	MethodACK
	// MethodSYNFIN is the SYN|FIN combination used by several older scanners
	// to slip past stateless filters (psad signature 100068, "SCAN SYN FIN").
	MethodSYNFIN
	// MethodFullXmas is the all-bits-set variant, psad signature 100069.
	MethodFullXmas
	// MethodOSFingerprint is URG|PSH|SYN|FIN, emitted by nmap's OS detection
	// probes (psad:5759-5760).
	MethodOSFingerprint
	// MethodCustomFlags is any other TCP combination, as produced by
	// nmap --scanflags. Reported with the raw flag byte rather than guessed at.
	MethodCustomFlags
	// MethodMixedFlags means the source used more than one flag combination.
	MethodMixedFlags
	// MethodUDP is nmap -sU.
	MethodUDP
	// MethodICMPSweep is a host sweep by ICMP message type: nmap -PE -PP -PM,
	// or the RFC 7707 probes that ask a host to identify itself.
	MethodICMPSweep
	// MethodProtocol is nmap -sO, an IP protocol scan.
	MethodProtocol
	// MethodMixed means several different families of probe were seen.
	MethodMixed
	// MethodFragmentedTCP is a TCP scan whose flag octet was never readable, as
	// nmap -f produces. The technique cannot be recovered; a flag byte that was
	// never read is not a NULL scan.
	MethodFragmentedTCP
	// MethodExtHeaderEvasion is a scan hidden behind more IPv6 extension
	// headers than any parser here walks: the port cannot be read, the host
	// answers anyway, and ordinary traffic never looks like this.
	MethodExtHeaderEvasion
)

// tcp flag combinations that name a method exactly.
const (
	flagsNULL        uint8 = 0
	flagsSYN         uint8 = TCPSyn
	flagsFIN         uint8 = TCPFin
	flagsACK         uint8 = TCPAck
	flagsXmas        uint8 = TCPFin | TCPPsh | TCPUrg
	flagsMaimon      uint8 = TCPFin | TCPAck
	flagsSYNFIN      uint8 = TCPSyn | TCPFin
	flagsFullXmas    uint8 = TCPSyn | TCPRst | TCPAck | TCPFin | TCPPsh | TCPUrg
	flagsOSFingerpri uint8 = TCPUrg | TCPPsh | TCPSyn | TCPFin
)

// methodFromFlags maps a constant TCP flag combination to a method.
func methodFromFlags(flags uint8) ScanMethod {
	switch flags {
	case flagsNULL:
		return MethodNULL
	case flagsSYN:
		return MethodSYN
	case flagsFIN:
		return MethodFIN
	case flagsACK:
		return MethodACK
	case flagsXmas:
		return MethodXmas
	case flagsMaimon:
		return MethodMaimon
	case flagsSYNFIN:
		return MethodSYNFIN
	case flagsFullXmas:
		return MethodFullXmas
	case flagsOSFingerpri:
		return MethodOSFingerprint
	default:
		return MethodCustomFlags
	}
}

// String implements fmt.Stringer with a short, stable identifier.
//
// These identifiers are part of the reported output and must stay stable:
// values are never repurposed, only added.
func (m ScanMethod) String() string {
	switch m {
	case MethodSYN:
		return "tcp-syn"
	case MethodFIN:
		return "tcp-fin"
	case MethodNULL:
		return "tcp-null"
	case MethodXmas:
		return "tcp-xmas"
	case MethodMaimon:
		return "tcp-maimon"
	case MethodACK:
		return "tcp-ack"
	case MethodSYNFIN:
		return "tcp-syn-fin"
	case MethodFullXmas:
		return "tcp-full-xmas"
	case MethodOSFingerprint:
		return "tcp-os-fingerprint"
	case MethodCustomFlags:
		return "tcp-custom-flags"
	case MethodMixedFlags:
		return "tcp-mixed-flags"
	case MethodUDP:
		return "udp"
	case MethodICMPSweep:
		return "icmp-sweep"
	case MethodProtocol:
		return "ip-protocol"
	case MethodMixed:
		return "mixed"
	case MethodFragmentedTCP:
		return "tcp-fragmented"
	case MethodExtHeaderEvasion:
		return "ipv6-extension-evasion"
	default:
		return "unknown"
	}
}

// Description returns a human-readable description, including the nmap options
// that produce it. Where several options are indistinguishable on the wire,
// all of them are listed rather than one being chosen.
//
// Each starts with the name the GUI gives the method (METHOD_LABELS in
// ui/opensnitch/portscan.py), so that the details of a block show it once, as
// the scan type, and puts the rest in parentheses: "equivalent to" nmap,
// because the packets show the technique, not the tool.
func (m ScanMethod) Description() string {
	switch m {
	case MethodSYN:
		return "TCP SYN scan (equivalent to nmap -sS, or to the -sT connect scan)"
	case MethodFIN:
		return "TCP FIN scan (equivalent to nmap -sF)"
	case MethodNULL:
		return "TCP NULL scan (equivalent to nmap -sN)"
	case MethodXmas:
		return "TCP Xmas scan (equivalent to nmap -sX)"
	case MethodMaimon:
		return "TCP Maimon scan (equivalent to nmap -sM)"
	case MethodACK:
		return "TCP ACK/Window scan (equivalent to nmap -sA or -sW, which are identical on the wire)"
	case MethodSYNFIN:
		return "TCP SYN+FIN scan (filter evasion)"
	case MethodFullXmas:
		return "TCP all-flags scan (an Xmas scan with every TCP flag set)"
	case MethodOSFingerprint:
		return "OS fingerprinting probe (equivalent to the TCP probes of nmap -O)"
	case MethodCustomFlags:
		return "TCP scan, custom flags (equivalent to nmap --scanflags)"
	case MethodMixedFlags:
		return "TCP scan, several flag combinations"
	case MethodUDP:
		return "UDP scan (equivalent to nmap -sU)"
	case MethodICMPSweep:
		return "ICMP host sweep (equivalent to nmap -PE, -PP or -PM, or an RFC 7707 probe)"
	case MethodProtocol:
		return "IP protocol scan (equivalent to nmap -sO)"
	case MethodMixed:
		return "Several scan techniques (combined by one source)"
	case MethodFragmentedTCP:
		return "Fragmented TCP scan (equivalent to nmap -f; the TCP flags were split across IP fragments and could not be read, so the exact technique is undetermined)"
	case MethodExtHeaderEvasion:
		return "Scan hidden behind IPv6 extension headers (a chain too long to walk, so the ports could not be read)"
	default:
		return "undetermined"
	}
}

// FlagsString renders the two flag masks the way scanlogd does
// (scanlogd.c:127-139): one character per TCP control bit, uppercase when the
// bit was set in every packet, lowercase when it was clear in every packet,
// and '?' when it varied.
//
// The character order is FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, matching the
// bit order of the TCP header's 13th octet.
func FlagsString(flagsOr, flagsAnd uint8) string {
	const names = "fsrpauec"
	out := make([]byte, len(names))
	for i := 0; i < len(names); i++ {
		mask := uint8(1) << uint(i)
		switch {
		case flagsOr&mask != flagsAnd&mask:
			out[i] = '?'
		case flagsOr&mask != 0:
			out[i] = names[i] - 32 // to upper case
		default:
			out[i] = names[i]
		}
	}
	return string(out)
}

// FlagsDetail renders a flag byte as a readable list, e.g. "SYN|FIN", or
// "NULL" when no bit is set.
func FlagsDetail(flags uint8) string {
	if flags == 0 {
		return "NULL"
	}
	names := [...]struct {
		bit  uint8
		name string
	}{
		{TCPFin, "FIN"}, {TCPSyn, "SYN"}, {TCPRst, "RST"}, {TCPPsh, "PSH"},
		{TCPAck, "ACK"}, {TCPUrg, "URG"}, {TCPEce, "ECE"}, {TCPCwr, "CWR"},
	}
	out := ""
	for _, n := range names {
		if flags&n.bit != 0 {
			if out != "" {
				out += "|"
			}
			out += n.name
		}
	}
	return out
}

// oneFamilyDominates reports that every family but one contributed a single
// probe, so naming the dominant technique is more informative than calling the
// whole thing mixed.
func oneFamilyDominates(st *sourceState) bool {
	counts := []uint32{st.tcpProbes, st.udpProbes, st.icmpProbes, st.evasionProbes}
	if st.protoScan {
		// A protocol scan is a technique in its own right and is never
		// incidental: it takes ProtoScanMinProtocols distinct protocols to set.
		return false
	}
	var top, rest uint32
	for _, c := range counts {
		if c > top {
			rest += top
			top = c
		} else {
			rest += c
		}
	}
	// Everything outside the leading family amounts to at most one probe.
	return top > 0 && rest <= 1
}

// describeMethod turns the accumulated per-source evidence into a method.
func describeMethod(st *sourceState) ScanMethod {
	families := 0
	if st.tcpProbes > 0 {
		families++
	}
	if st.udpProbes > 0 {
		families++
	}
	if st.protoScan {
		families++
	}
	// ICMP is ONE family whether it merely scored or crossed as a sweep.
	// Counting the sweep flag separately from the probes that set it would make
	// every ICMP-only source a "mixed" one.
	if st.icmpProbes > 0 || st.icmpSweep {
		families++
	}
	if st.evasionProbes > 0 {
		families++
	}

	// A family counts only if it sent more than one probe: otherwise one extra
	// datagram would turn "TCP SYN scan" into "several techniques combined", the
	// cheapest way to tell the victim less.
	switch {
	case families > 1 && !oneFamilyDominates(st):
		return MethodMixed
	case st.protoScan:
		return MethodProtocol
	case st.icmpSweep:
		return MethodICMPSweep
	case st.evasionProbes > st.tcpProbes && st.evasionProbes > st.udpProbes:
		return MethodExtHeaderEvasion
	case st.udpProbes > st.tcpProbes:
		// The dominant family, not merely a present one: a TCP scan carrying one UDP
		// datagram is a TCP scan.
		return MethodUDP
	case st.tcpProbes == 0:
		return MethodUnknown
	case !st.flagsSeen:
		// TCP probes were counted but the flag octet was never readable:
		// nmap -f splits the TCP header so that the flags fall in a later
		// fragment. Reporting MethodNULL here -- which an all-zero flags field
		// would produce -- would invent a technique that was never observed.
		return MethodFragmentedTCP
	case st.flagsOr != st.flagsAnd:
		// The combination varied between packets. Naming a single technique
		// here would be a guess; nmap --scanflags and multi-mode scanners both
		// land in this case legitimately.
		return MethodMixedFlags
	default:
		return methodFromFlags(st.flagsOr)
	}
}

// CustomFlagsLabel renders a MethodCustomFlags method with its actual bits,
// so the report says what was seen instead of only that it was unusual.
func CustomFlagsLabel(flags uint8) string {
	return fmt.Sprintf("TCP scan with flags %s (0x%02x)", FlagsDetail(flags), flags)
}
