//go:build linux

package portscan

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// scannerMAC is a locally-administered address, so it cannot collide with a
// real vendor prefix if this test output is ever pasted into a bug report.
var scannerMAC = [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}

// fullEvent is a rich event: every optional field is populated, so a test can
// blank out exactly the one it is about.
func fullEvent() *ScanEvent {
	first := time.Unix(1700000000, 0)
	return &ScanEvent{
		Src:            attacker,
		SrcMAC:         scannerMAC,
		HasMAC:         true,
		MACIsSourceOwn: true,
		Method:         MethodSYN,
		MethodDetail:   "tcp-syn",
		FlagsOr:        TCPSyn,
		FlagsAnd:       TCPSyn,
		FlagsSummary:   "******S*",
		DistinctPorts:  9,
		MinPort:        21,
		MaxPort:        113,
		SamplePorts:    []uint16{21, 22, 23, 25, 80},
		Protocols:      1,
		Score:          108,
		Anomalies:      AnomalyNoTCPOptions,
		IfaceIndex:     2,
		Targets:        []netip.Addr{victim, victim6},
		FirstSeenNs:    1000,
		LastSeenNs:     9000,
		FirstSeen:      first,
		LastSeen:       first.Add(2 * time.Second),
		HasTCPEvidence: true,
		BlockEligible:  true,
	}
}

// ---------------------------------------------------------------------------
// ToProtocol
// ---------------------------------------------------------------------------

func TestToProtocolNilEventIsNil(t *testing.T) {
	if got := ToProtocol(nil, "eth0", time.Hour); got != nil {
		t.Fatalf("ToProtocol(nil) = %v, want nil", got)
	}
}

func TestToProtocolCarriesEveryField(t *testing.T) {
	ev := fullEvent()
	pb := ToProtocol(ev, "eth0", 4*time.Hour)

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"SrcIp", pb.SrcIp, attacker.String()},
		{"SrcMac", pb.SrcMac, "02:11:22:33:44:55"},
		{"SrcMacIsSourceOwn", pb.SrcMacIsSourceOwn, true},
		{"Method", pb.Method, "tcp-syn"},
		{"MethodDetail", pb.MethodDetail, "tcp-syn"},
		{"FlagsSummary", pb.FlagsSummary, "******S*"},
		{"DistinctPorts", pb.DistinctPorts, uint32(9)},
		{"MinPort", pb.MinPort, uint32(21)},
		{"MaxPort", pb.MaxPort, uint32(113)},
		{"Protocols", pb.Protocols, uint32(1)},
		{"IsProtocolScan", pb.IsProtocolScan, false},
		{"Score", pb.Score, uint32(108)},
		{"Interface", pb.Interface, "eth0"},
		{"HasTcpEvidence", pb.HasTcpEvidence, true},
		{"BlockEligible", pb.BlockEligible, true},
		{"BlockDurationSeconds", pb.BlockDurationSeconds, uint32(14400)},
		{"FirstSeenUnixnano", pb.FirstSeenUnixnano, ev.FirstSeen.UnixNano()},
		{"LastSeenUnixnano", pb.LastSeenUnixnano, ev.LastSeen.UnixNano()},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	if len(pb.SamplePorts) != len(ev.SamplePorts) {
		t.Fatalf("SamplePorts = %v, want %d entries", pb.SamplePorts, len(ev.SamplePorts))
	}
	for i, p := range ev.SamplePorts {
		if pb.SamplePorts[i] != uint32(p) {
			t.Errorf("SamplePorts[%d] = %d, want %d", i, pb.SamplePorts[i], p)
		}
	}
	if len(pb.Targets) != 2 || pb.Targets[0] != victim.String() || pb.Targets[1] != victim6.String() {
		t.Errorf("Targets = %v, want [%s %s]", pb.Targets, victim, victim6)
	}
	if len(pb.Anomalies) != 1 || pb.Anomalies[0] != "syn-without-tcp-options" {
		t.Errorf("Anomalies = %v, want [syn-without-tcp-options]", pb.Anomalies)
	}
}

// TestToProtocolNeverAttributesARouterMAC is the honesty constraint that must
// survive the conversion.
//
// When the source is not on-link, the MAC in the frame belongs to the last
// router, not to the scanner. The address still travels -- it is a real fact
// about the packet -- but it travels with the flag that says whose it is, so no
// client can present it as identifying the scanner.
func TestToProtocolNeverAttributesARouterMAC(t *testing.T) {
	ev := fullEvent()
	ev.MACIsSourceOwn = false
	pb := ToProtocol(ev, "eth0", time.Hour)

	if pb.SrcMacIsSourceOwn {
		t.Fatalf("SrcMacIsSourceOwn must be false for an off-link source")
	}
	if pb.SrcMac == "" {
		t.Fatalf("the observed MAC must still be reported, flagged rather than dropped")
	}
}

func TestToProtocolOmitsAbsentMAC(t *testing.T) {
	ev := fullEvent()
	ev.HasMAC = false
	ev.MACIsSourceOwn = false
	pb := ToProtocol(ev, "", time.Hour)

	if pb.SrcMac != "" {
		t.Fatalf("SrcMac = %q, want empty when no link-layer address was seen", pb.SrcMac)
	}
}

// TestToProtocolPropagatesSuppressionCount: without it a client would present
// one alert as the only scan in progress while ninety-nine were withheld.
func TestToProtocolPropagatesSuppressionCount(t *testing.T) {
	ev := fullEvent()
	ev.SuppressedSince = 97
	if got := ToProtocol(ev, "", time.Hour).SuppressedSince; got != 97 {
		t.Fatalf("SuppressedSince = %d, want 97", got)
	}
}

func TestToProtocolZeroTimestampsStayZero(t *testing.T) {
	ev := fullEvent()
	ev.FirstSeen, ev.LastSeen = time.Time{}, time.Time{}
	pb := ToProtocol(ev, "", time.Hour)
	if pb.FirstSeenUnixnano != 0 || pb.LastSeenUnixnano != 0 {
		t.Fatalf("unset times must stay zero, got %d and %d", pb.FirstSeenUnixnano, pb.LastSeenUnixnano)
	}
}

func TestToProtocolEmptyCollectionsAreNotNil(t *testing.T) {
	ev := &ScanEvent{Src: attacker, Method: MethodUDP}
	pb := ToProtocol(ev, "", time.Hour)
	if pb.SamplePorts == nil || pb.Targets == nil || pb.Anomalies == nil {
		t.Fatalf("empty collections must serialise as empty, not nil: %+v", pb)
	}
}

func TestToProtocolBlockDurationRoundsToSeconds(t *testing.T) {
	ev := fullEvent()
	for _, tc := range []struct {
		d    time.Duration
		want uint32
	}{
		{4 * time.Hour, 14400},
		{90 * time.Second, 90},
		{1500 * time.Millisecond, 1},
		{0, 0},
	} {
		if got := ToProtocol(ev, "", tc.d).BlockDurationSeconds; got != tc.want {
			t.Errorf("BlockDurationSeconds(%v) = %d, want %d", tc.d, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// anomaly identifiers
// ---------------------------------------------------------------------------

// TestAnomalyStringsAreStable pins the wire identifiers. They appear in the
// user interface and in the coverage report, so renaming one silently would
// break both.
func TestAnomalyStringsAreStable(t *testing.T) {
	got := AnomalyStrings(AnomalyFragment | AnomalyExtHeaderChain | AnomalyTruncated | AnomalyNoTCPOptions)
	want := []string{
		"ip-fragment",
		"ipv6-extension-header-chain",
		"truncated-header",
		"syn-without-tcp-options",
	}
	if len(got) != len(want) {
		t.Fatalf("AnomalyStrings = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AnomalyStrings = %v, want %v", got, want)
		}
	}

	if n := len(AnomalyStrings(0)); n != 0 {
		t.Fatalf("an empty mask must render as no identifiers, got %d", n)
	}
	if got := AnomalyStrings(AnomalyTruncated); len(got) != 1 || got[0] != "truncated-header" {
		t.Fatalf("AnomalyStrings(AnomalyTruncated) = %v", got)
	}
}

// TestEveryAnomalyBitHasAName guards against adding a bit to probe.go without
// adding its identifier here: an unnamed anomaly would be silently invisible.
func TestEveryAnomalyBitHasAName(t *testing.T) {
	var all Anomaly
	for _, n := range anomalyNames {
		all |= n.bit
	}
	for bit := Anomaly(1); bit != 0; bit <<= 1 {
		if bit > lastAnomalyBit {
			break
		}
		if all&bit == 0 {
			t.Fatalf("anomaly bit %#x has no identifier in anomalyNames", uint16(bit))
		}
	}
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

// TestSummaryNeverAccuses is a load-bearing test, not a style check.
//
// With nmap -D, nmap -S, an idle scan or an FTP bounce, the address in the
// packets belongs to an uninvolved third party. Any wording that names it as
// the attacker turns a detection into an accusation the packets do not support.
func TestSummaryNeverAccuses(t *testing.T) {
	forbidden := []string{"attacker", "hacker", "intruder", "malicious", "criminal"}
	outcomes := []BlockOutcome{OutcomeNone, OutcomeProposed, OutcomeApplied, OutcomeRefused}

	for _, outcome := range outcomes {
		ev := fullEvent()
		ev.SuppressedSince = 3
		ev.Anomalies = AnomalyFragment | AnomalyTruncated
		title, body := Summary(ev, outcome, 4*time.Hour)
		text := strings.ToLower(title + "\n" + body)
		for _, w := range forbidden {
			if strings.Contains(text, w) {
				t.Fatalf("outcome %q: the summary contains %q:\n%s", outcome, w, body)
			}
		}
		if !strings.Contains(body, "from "+attacker.String()) {
			t.Fatalf("outcome %q: the summary must state the address plainly:\n%s", outcome, body)
		}
	}
}

func TestSummaryShowsTheMACOnlyWhenItIsTheSource(t *testing.T) {
	ev := fullEvent()
	_, body := Summary(ev, OutcomeProposed, time.Hour)
	if !strings.Contains(body, "(02:11:22:33:44:55)") {
		t.Fatalf("an on-link source's MAC must be shown as its own:\n%s", body)
	}
	if strings.Contains(body, "last hop") {
		t.Fatalf("an on-link MAC must not be described as a last hop:\n%s", body)
	}

	ev.MACIsSourceOwn = false
	_, body = Summary(ev, OutcomeProposed, time.Hour)
	if !strings.Contains(body, "last hop 02:11:22:33:44:55") {
		t.Fatalf("an off-link MAC must be labelled as the last hop:\n%s", body)
	}

	ev.HasMAC = false
	_, body = Summary(ev, OutcomeProposed, time.Hour)
	if strings.Contains(body, "02:11:22:33:44:55") {
		t.Fatalf("no MAC was observed; none may appear:\n%s", body)
	}
}

func TestSummaryDescribesPortsAndProtocols(t *testing.T) {
	ev := fullEvent()
	_, body := Summary(ev, OutcomeNone, time.Hour)
	if !strings.Contains(body, "9 ports probed between 21 and 113") {
		t.Fatalf("the port range must be stated:\n%s", body)
	}
	if !strings.Contains(body, "TCP flags ******S*") {
		t.Fatalf("the flag rendering must be included:\n%s", body)
	}

	// A single port carries no range.
	ev.DistinctPorts, ev.MinPort, ev.MaxPort = 1, 80, 80
	_, body = Summary(ev, OutcomeNone, time.Hour)
	if strings.Contains(body, "between") {
		t.Fatalf("a single port has no range to state:\n%s", body)
	}

	// A protocol scan has no ports at all: saying "0 ports probed" would be
	// both wrong and confusing.
	ev.IsProtocolScan, ev.Protocols, ev.Method = true, 7, MethodProtocol
	_, body = Summary(ev, OutcomeNone, time.Hour)
	if !strings.Contains(body, "7 distinct IP protocols probed") {
		t.Fatalf("a protocol scan must be described as such:\n%s", body)
	}
	if strings.Contains(body, "ports probed") {
		t.Fatalf("a protocol scan must not be described in ports:\n%s", body)
	}
}

func TestSummaryStatesTheOutcome(t *testing.T) {
	ev := fullEvent()
	for _, tc := range []struct {
		outcome BlockOutcome
		want    string
	}{
		{OutcomeApplied, "Blocked for 4h."},
		{OutcomeProposed, "Block this source for 4h?"},
		{OutcomeRefused, "Not blocked."},
	} {
		if _, body := Summary(ev, tc.outcome, 4*time.Hour); !strings.Contains(body, tc.want) {
			t.Errorf("outcome %q: want %q in:\n%s", tc.outcome, tc.want, body)
		}
	}

	// "none" is the alert-only mode: no claim is made about blocking at all.
	_, body := Summary(ev, OutcomeNone, 4*time.Hour)
	for _, unwanted := range []string{"Blocked", "Not blocked", "Block this source"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("alert-only mode must not mention blocking (%q):\n%s", unwanted, body)
		}
	}
}

func TestSummaryReportsSuppressedAlerts(t *testing.T) {
	ev := fullEvent()
	ev.SuppressedSince = 42
	_, body := Summary(ev, OutcomeProposed, time.Hour)
	if !strings.Contains(body, "42 further scan alert(s) were suppressed") {
		t.Fatalf("the suppressed count must be surfaced:\n%s", body)
	}

	ev.SuppressedSince = 0
	_, body = Summary(ev, OutcomeProposed, time.Hour)
	if strings.Contains(body, "suppressed") {
		t.Fatalf("nothing was suppressed; nothing must be said:\n%s", body)
	}
}

func TestSummaryListsEvasionSigns(t *testing.T) {
	ev := fullEvent()
	ev.Anomalies = AnomalyFragment | AnomalyTruncated
	_, body := Summary(ev, OutcomeNone, time.Hour)
	if !strings.Contains(body, "Evasion signs: ip-fragment, truncated-header") {
		t.Fatalf("evasion signs must be listed:\n%s", body)
	}

	ev.Anomalies = 0
	_, body = Summary(ev, OutcomeNone, time.Hour)
	if strings.Contains(body, "Evasion signs") {
		t.Fatalf("no anomaly was seen; none must be claimed:\n%s", body)
	}
}

func TestFormatDuration(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{4 * time.Hour, "4h"},
		{time.Hour, "1h"},
		{90 * time.Minute, "90m"},
		{30 * time.Second, "30s"},
		{2500 * time.Millisecond, "2.5s"},
	} {
		if got := formatDuration(tc.d); got != tc.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestFormatMAC(t *testing.T) {
	if got := formatMAC(scannerMAC, true); got != "02:11:22:33:44:55" {
		t.Fatalf("formatMAC = %q", got)
	}
	if got := formatMAC(scannerMAC, false); got != "" {
		t.Fatalf("formatMAC with has=false = %q, want empty", got)
	}
}

// TestSummaryIsSelfContained: the notification is often all the user ever sees,
// so it must carry the address, the technique and the scale without needing the
// event log.
func TestSummaryIsSelfContained(t *testing.T) {
	title, body := Summary(fullEvent(), OutcomeProposed, 4*time.Hour)
	if title == "" {
		t.Fatalf("the notification needs a title")
	}
	for _, want := range []string{"tcp-syn", attacker.String(), "9 ports"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the summary omits %q:\n%s", want, body)
		}
	}
}
