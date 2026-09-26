//go:build linux

package portscan

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// scanModuleSource is the C program this package must agree with.
const scanModuleSource = "../../ebpf_prog/opensnitch-scan.c"

func readScanModuleSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(scanModuleSource))
	if err != nil {
		t.Skipf("the eBPF source is not available from here (%v)", err)
	}
	return string(b)
}

// TestEbpfContractConstantsMatchC checks that every value shared between the
// Go decoder and the C program still agrees.
//
// The two halves communicate through a packed binary record with no
// self-describing framing, so a divergence produces no error at all: it
// produces plausible-looking probes with the wrong ports, the wrong flags or
// the wrong address family. That is exactly the failure mode this project
// refuses to ship, so the agreement is asserted rather than assumed.
// TestFillMapsEveryAnomalyBit: each anomaly bit of a ring buffer record must
// reach the Probe as the matching Anomaly. The constants are checked against
// the C source elsewhere; this is the mapping between them, in probeEvent.fill,
// where a dropped line made the GUI never hear of that evasion sign.
func TestFillMapsEveryAnomalyBit(t *testing.T) {
	cases := []struct {
		wire uint16
		want Anomaly
	}{
		{probeAnomalyFragment, AnomalyFragment},
		{probeAnomalyExtHdr, AnomalyExtHeaderChain},
		{probeAnomalyTruncated, AnomalyTruncated},
		{probeAnomalyNoTCPOpts, AnomalyNoTCPOptions},
		{probeAnomalyFirstFrag, AnomalyFirstFragment},
		{probeAnomalyVLANDepth, AnomalyVLANDepth},
		{probeAnomalyTrailer, AnomalyTrailer},
	}
	var every Anomaly
	for _, c := range cases {
		every |= c.want
		ev := probeEvent{Anomalies: c.wire}
		var p Probe
		if !ev.fill(&p) {
			t.Fatalf("fill refused a record with anomaly bit %#x", c.wire)
		}
		if p.Anomalies != c.want {
			t.Errorf("wire anomaly %#x became %#x, want %#x", c.wire, p.Anomalies, c.want)
		}
	}
	for bit := Anomaly(1); bit <= lastAnomalyBit; bit <<= 1 {
		if every&bit == 0 {
			t.Errorf("anomaly %#x has no wire bit in this table", bit)
		}
	}
}

func TestEbpfContractConstantsMatchC(t *testing.T) {
	src := readScanModuleSource(t)

	cases := []struct {
		cName string
		goVal int
	}{
		{"PROBE_ANOMALY_FRAGMENT", probeAnomalyFragment},
		{"PROBE_ANOMALY_EXTHDR_CHAIN", probeAnomalyExtHdr},
		{"PROBE_ANOMALY_TRUNCATED", probeAnomalyTruncated},
		{"PROBE_ANOMALY_NO_TCP_OPTIONS", probeAnomalyNoTCPOpts},
		{"PROBE_ANOMALY_FIRST_FRAGMENT", probeAnomalyFirstFrag},
		{"PROBE_ANOMALY_VLAN_DEPTH", probeAnomalyVLANDepth},
		{"PROBE_ANOMALY_TRAILER", probeAnomalyTrailer},
		{"PROBE_FLAG_HAS_MAC", probeFlagHasMAC},
		{"PROBE_FLAG_TCP_FLAGS_OK", probeFlagTCPFlagsOK},
		{"PROBE_FLAG_IPV6", probeFlagIPv6},
	}
	for _, tc := range cases {
		t.Run(tc.cName, func(t *testing.T) {
			got, ok := parseCShiftDefine(src, tc.cName)
			if !ok {
				t.Fatalf("%s is not defined in %s", tc.cName, scanModuleSource)
			}
			if got != tc.goVal {
				t.Errorf("%s = %d in C, %d in Go", tc.cName, got, tc.goVal)
			}
		})
	}

	// The config array indices decide which knob the daemon writes.
	idx := []struct {
		cName string
		goVal int
	}{
		{"CFG_ENABLED", cfgEnabled},
		{"CFG_MAX_PER_SEC", cfgMaxPerSec},
		{"CFG_GRACE_UNTIL_LO", cfgGraceUntilLo},
		{"CFG_GRACE_UNTIL_HI", cfgGraceUntilHi},
		{"CFG_MAX_TOTAL_PER_SEC", cfgMaxTotalPerSec},
	}
	for _, tc := range idx {
		got, ok := parseCIntDefine(src, tc.cName)
		if !ok {
			t.Errorf("%s is not defined in %s", tc.cName, scanModuleSource)
			continue
		}
		if got != tc.goVal {
			t.Errorf("%s = %d in C, %d in Go", tc.cName, got, tc.goVal)
		}
	}
}

// TestEbpfExtensionHeaderBoundMatchesGoParser: kernel and userspace must walk
// the same number of IPv6 extension headers, or they would disagree about
// which packets carry an over-long chain -- and that chain is the Topera
// evasion signature, so disagreeing means one of the two sources silently
// misses it.
func TestEbpfExtensionHeaderBoundMatchesGoParser(t *testing.T) {
	src := readScanModuleSource(t)
	got, ok := parseCIntDefine(src, "MAX_EXT_HEADERS")
	if !ok {
		t.Fatalf("MAX_EXT_HEADERS is not defined in %s", scanModuleSource)
	}
	if got != maxExtHeaders {
		t.Errorf("MAX_EXT_HEADERS = %d in C, maxExtHeaders = %d in Go", got, maxExtHeaders)
	}

	// The byte bound matters more than the header count: it is what the
	// AF_PACKET capture length is derived from, and a disagreement means the
	// fallback stops seeing exactly the packets that are trying to hide.
	got, ok = parseCIntDefine(src, "MAX_EXT_CHAIN_BYTES")
	if !ok {
		t.Fatalf("MAX_EXT_CHAIN_BYTES is not defined in %s", scanModuleSource)
	}
	if got != maxExtChainBytes {
		t.Errorf("MAX_EXT_CHAIN_BYTES = %d in C, maxExtChainBytes = %d in Go", got, maxExtChainBytes)
	}
}

// TestProbeEventLayout pins the record size and field offsets.
//
// The C struct is __attribute__((packed)), so the Go mirror must have no
// padding either. binary.Size returns -1 for a type that cannot be encoded
// with a fixed layout, which would itself be a failure.
func TestProbeEventLayout(t *testing.T) {
	if probeEventSize <= 0 {
		t.Fatalf("probeEvent has no fixed binary layout (binary.Size = %d)", probeEventSize)
	}
	// 8 + 16 + 16 + 6 + 2 + 2 + 4 + 1 + 1 + 2 + 2 + 2
	const want = 62
	if probeEventSize != want {
		t.Errorf("probeEvent encodes to %d bytes, want %d; the C struct and its Go mirror have diverged",
			probeEventSize, want)
	}
}

// TestProbeEventDecoding feeds a hand-built record through the decoder, so the
// field order is checked and not merely the total size. A struct whose fields
// were transposed would keep the same size and pass a size check alone.
func TestProbeEventDecoding(t *testing.T) {
	rec := make([]byte, probeEventSize)
	binary.NativeEndian.PutUint64(rec[0:8], 123456789)
	// ::ffff:192.0.2.66 as the source
	src16 := netip.MustParseAddr("192.0.2.66").As16()
	copy(rec[8:24], src16[:])
	dst16 := netip.MustParseAddr("192.0.2.1").As16()
	copy(rec[24:40], dst16[:])
	copy(rec[40:46], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	binary.NativeEndian.PutUint16(rec[46:48], 40000) // sport
	binary.NativeEndian.PutUint16(rec[48:50], 22)    // dport
	binary.NativeEndian.PutUint32(rec[50:54], 7)     // ifindex
	rec[54] = ProtoTCP
	rec[55] = TCPSyn
	binary.NativeEndian.PutUint16(rec[56:58], probeAnomalyNoTCPOpts)
	binary.NativeEndian.PutUint16(rec[58:60], probeFlagHasMAC|probeFlagTCPFlagsOK)

	var ev probeEvent
	if err := decodeProbeEvent(rec, &ev); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	// Deliberately pre-dirtied: the read loop reuses one Probe, so fill must
	// overwrite every field rather than only the ones it sets.
	p := Probe{
		TimeNs: 1 << 40, SrcPort: 9999, DstPort: 9999, Proto: ProtoUDP,
		TCPFlags: 0xff, TCPFlagsValid: true, HasMAC: true,
		SrcMAC: [6]byte{9, 9, 9, 9, 9, 9}, IfaceIndex: 99,
		Anomalies: AnomalyFragment | AnomalyExtHeaderChain,
		Src:       netip.MustParseAddr("203.0.113.1"),
		Dst:       netip.MustParseAddr("203.0.113.2"),
	}
	if !ev.fill(&p) {
		t.Fatal("fill rejected a well-formed record")
	}
	if p.Anomalies&(AnomalyFragment|AnomalyExtHeaderChain) != 0 {
		t.Errorf("anomalies from the previous record survived: %#x", p.Anomalies)
	}
	if got := p.Src.String(); got != "192.0.2.66" {
		t.Errorf("Src = %s, want 192.0.2.66", got)
	}
	if got := p.Dst.String(); got != "192.0.2.1" {
		t.Errorf("Dst = %s, want 192.0.2.1", got)
	}
	if p.DstPort != 22 || p.SrcPort != 40000 {
		t.Errorf("ports = %d -> %d, want 40000 -> 22", p.SrcPort, p.DstPort)
	}
	if p.Proto != ProtoTCP || p.TCPFlags != TCPSyn {
		t.Errorf("proto/flags = %d/%#02x, want %d/%#02x", p.Proto, p.TCPFlags, ProtoTCP, TCPSyn)
	}
	if !p.TCPFlagsValid {
		t.Error("TCPFlagsValid is false although PROBE_FLAG_TCP_FLAGS_OK was set")
	}
	if !p.HasMAC || p.SrcMAC != [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} {
		t.Errorf("MAC = %v (has=%v), want aa:bb:cc:dd:ee:ff", p.SrcMAC, p.HasMAC)
	}
	if p.IfaceIndex != 7 {
		t.Errorf("IfaceIndex = %d, want 7", p.IfaceIndex)
	}
	if p.Anomalies&AnomalyNoTCPOptions == 0 {
		t.Error("the SYN-without-options anomaly did not survive decoding")
	}
}

// TestProbeEventUnreadableFlags: a record whose PROBE_FLAG_TCP_FLAGS_OK is
// clear must not be treated as a NULL scan. This is the fragmented-scan
// honesty rule, enforced at the kernel boundary.
func TestProbeEventUnreadableFlags(t *testing.T) {
	rec := make([]byte, probeEventSize)
	src16 := netip.MustParseAddr("192.0.2.66").As16()
	copy(rec[8:24], src16[:])
	dst16 := netip.MustParseAddr("192.0.2.1").As16()
	copy(rec[24:40], dst16[:])
	rec[54] = ProtoTCP
	rec[55] = 0 // no bits, but they were never read
	binary.NativeEndian.PutUint16(rec[56:58], probeAnomalyTruncated)
	binary.NativeEndian.PutUint16(rec[58:60], probeFlagHasMAC) // TCP_FLAGS_OK absent

	var ev probeEvent
	if err := decodeProbeEvent(rec, &ev); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	// Pre-dirtied with TCPFlagsValid set, which is exactly the state the
	// previous record would leave behind and the one that would turn an
	// unreadable flag octet into a reported NULL scan.
	p := Probe{TCPFlagsValid: true, TCPFlags: TCPSyn}
	if !ev.fill(&p) {
		t.Fatal("fill rejected a well-formed record")
	}
	if p.TCPFlagsValid {
		t.Fatal("TCPFlagsValid is true although the kernel reported the flags as unread")
	}
	if p.Anomalies&AnomalyTruncated == 0 {
		t.Error("the truncation anomaly did not survive decoding")
	}
}

// TestScanModuleNeverChangesVerdicts checks by inspection that the eBPF
// program returns TC_ACT_OK on every path.
//
// Enforcement is an nftables rule the daemon installs, so that a user can see,
// audit and undo what their firewall is doing. A drop hidden inside a BPF
// program would be invisible to nft, to any external audit, and to the user.
func TestScanModuleNeverChangesVerdicts(t *testing.T) {
	src := readScanModuleSource(t)
	for _, forbidden := range []string{"TC_ACT_SHOT", "TC_ACT_STOLEN", "XDP_DROP", "TC_ACT_REDIRECT"} {
		if regexp.MustCompile(`\b` + forbidden + `\b`).MatchString(src) {
			t.Errorf("the scan module uses %s: detection must never change a packet's verdict, "+
				"blocking belongs in the nftables rule the daemon installs", forbidden)
		}
	}
}

// parseCShiftDefine reads "#define NAME (1 << n)".
func parseCShiftDefine(src, name string) (int, bool) {
	re := regexp.MustCompile(`#define\s+` + regexp.QuoteMeta(name) + `\s+\(\s*1\s*<<\s*(\d+)\s*\)`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return 1 << n, true
}

// parseCIntDefine reads "#define NAME <int>".
func parseCIntDefine(src, name string) (int, bool) {
	re := regexp.MustCompile(`#define\s+` + regexp.QuoteMeta(name) + `\s+(\d+)\b`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// TestEveryAnomalyBitExistsOnBothSides keeps a security rule from being
// applied to half the system.
//
// This file and ebpf_prog/opensnitch-scan.c carry two independent parsers of
// the same protocols. The design says their verdicts are identical by
// construction, and something has to enforce it. A rule such as bounding the
// payload by the declared IP length, the RST mask or the first-fragment marker
// could otherwise go into the Go parser alone, and a differential harness that
// only replayed the corpus through ParseEthernet would not see it.
//
// Comparing "the four anomaly bits I know about" cannot report a constant
// nobody thought to list. This test enumerates the Go side and requires a
// counterpart for every entry, so adding a bit without adding it to the
// kernel is a failing test rather than a silent divergence.
func TestEveryAnomalyBitExistsOnBothSides(t *testing.T) {
	src := readScanModuleSource(t)

	// Every Anomaly the Go side defines, with the C macro that must match it.
	// Adding a value to probe.go without adding a line here fails
	// TestEveryAnomalyBitHasAName, which enumerates the same set from
	// anomalyNames.
	want := map[string]Anomaly{
		"PROBE_ANOMALY_FRAGMENT":       AnomalyFragment,
		"PROBE_ANOMALY_EXTHDR_CHAIN":   AnomalyExtHeaderChain,
		"PROBE_ANOMALY_TRUNCATED":      AnomalyTruncated,
		"PROBE_ANOMALY_NO_TCP_OPTIONS": AnomalyNoTCPOptions,
		"PROBE_ANOMALY_FIRST_FRAGMENT": AnomalyFirstFragment,
		"PROBE_ANOMALY_VLAN_DEPTH":     AnomalyVLANDepth,
		"PROBE_ANOMALY_TRAILER":        AnomalyTrailer,
	}

	// Every bit the Go side can set must be in the table above: otherwise the
	// table itself becomes the thing that goes stale.
	var covered Anomaly
	for _, v := range want {
		covered |= v
	}
	for bit := Anomaly(1); bit != 0 && bit <= lastAnomalyBit; bit <<= 1 {
		if covered&bit == 0 {
			t.Fatalf("anomaly bit %#x is defined in Go but has no C counterpart listed here", uint16(bit))
		}
	}

	for cName, goVal := range want {
		got, ok := parseCShiftDefine(src, cName)
		if !ok {
			t.Errorf("%s is not defined in %s: a Go anomaly bit with no kernel counterpart means the two parsers disagree",
				cName, scanModuleSource)
			continue
		}
		if uint16(got) != uint16(goVal) {
			t.Errorf("%s = %d in C, %d in Go", cName, got, uint16(goVal))
		}
	}
}

// TestSharedParserBoundsMatchC enumerates every constant that both parsers use
// to decide how far to read. A divergence in any of them means one source sees
// a packet the other does not.
func TestSharedParserBoundsMatchC(t *testing.T) {
	src := readScanModuleSource(t)
	for _, tc := range []struct {
		cName string
		goVal int
	}{
		{"MAX_EXT_HEADERS", maxExtHeaders},
		{"MAX_EXT_CHAIN_BYTES", maxExtChainBytes},
		{"MAX_VLAN_TAGS", maxVLANTags},
	} {
		got, ok := parseCIntDefine(src, tc.cName)
		if !ok {
			t.Errorf("%s is not defined in %s", tc.cName, scanModuleSource)
			continue
		}
		if got != tc.goVal {
			t.Errorf("%s = %d in C, %d in Go", tc.cName, got, tc.goVal)
		}
	}
}

// TestKernelParserBoundsThePayload checks, by reading the source, that the C
// parser consults the length fields at all.
//
// It is a crude test and it is deliberate: the property it guards -- "the
// kernel parser bounds its reads by the declared length" -- is easy to lose
// on the C side while the Go side keeps it, and a crude check that fails
// loudly is worth more than an elegant one nobody wrote. The real proof is the
// differential harness in cparse_test.go, which runs both parsers over the
// same frames.
func TestKernelParserBoundsThePayload(t *testing.T) {
	src := readScanModuleSource(t)
	for _, want := range []string{
		"tot_len",     // parse_ipv4 reads Total Length
		"payload_len", // parse_ipv6 reads Payload Length
		"__u32 avail", // parse_transport takes the declared remainder
		"NEXTHDR_HOP", // ... or the comment naming the kernel's own rule
		"PROBE_ANOMALY_TRAILER",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("%s does not mention %q: the kernel parser may not be bounding its reads",
				scanModuleSource, want)
		}
	}
}

// TestHtonsIsNetworkOrderInMemory holds on any architecture: whatever the host
// order, the value htons returns must sit in memory as the two bytes of network
// order. An unconditional byte swap would be right only on little-endian
// hosts.
func TestHtonsIsNetworkOrderInMemory(t *testing.T) {
	for _, v := range []uint16{0x0003, 0x0800, 0x86dd, 0x1234} {
		var mem, want [2]byte
		binary.NativeEndian.PutUint16(mem[:], htons(v))
		binary.BigEndian.PutUint16(want[:], v)
		if mem != want {
			t.Errorf("htons(%#04x) is % x in memory, want % x", v, mem, want)
		}
	}
}
