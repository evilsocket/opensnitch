//go:build linux

package main

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/portscan"
	"github.com/evilsocket/opensnitch/daemon/tasks/portscanblocks"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

// TestScanForUIKeepsEveryFieldInPlace: the details of a block reuse the
// PortScan field names so the user interface reads both the same way. Every
// field is given a distinct value, so two fields swapped in the copy (min and
// max port, say) show as a mismatch, and every name sent must be a PortScan
// field.
func TestScanForUIKeepsEveryFieldInPlace(t *testing.T) {
	p := &protocol.PortScan{
		SrcIp:             "192.0.2.1",
		SrcMac:            "02:00:00:00:00:01",
		SrcMacIsSourceOwn: true,
		Method:            "syn",
		MethodDetail:      "TCP SYN scan",
		FlagsSummary:      "******S*",
		DistinctPorts:     3,
		MinPort:           5,
		MaxPort:           7,
		SamplePorts:       []uint32{11, 13},
		Protocols:         17,
		IsProtocolScan:    true,
		Score:             19,
		Interface:         "eth0",
		Targets:           []string{"192.0.2.2"},
		FirstSeenUnixnano: 23,
		LastSeenUnixnano:  29,
		Anomalies:         []string{"ip-fragment"},
		HasTcpEvidence:    true,
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]interface{}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(scanForUI(p))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 18 {
		t.Errorf("%d fields sent, want 18: %v", len(got), got)
	}
	for k, v := range got {
		w, ok := want[k]
		if !ok {
			t.Errorf("%q is not a PortScan field", k)
			continue
		}
		if !reflect.DeepEqual(v, w) {
			t.Errorf("%s = %v, PortScan has %v", k, v, w)
		}
	}
}

// TestDetectionsForUI: the history the user interface receives leaves out the
// sources blocked right now, which it lists as blocks; a block that ended on
// its own is "ended", not "blocked"; and each row says whether it can be
// blocked without force, or at all.
func TestDetectionsForUI(t *testing.T) {
	at := time.Unix(1700000000, 0)
	ev := func(a string, eligible bool) *portscan.ScanEvent {
		return &portscan.ScanEvent{Src: netip.MustParseAddr(a), Method: portscan.MethodXmas,
			MethodDetail: portscan.MethodXmas.Description(), BlockEligible: eligible}
	}
	blockedNow := netip.MustParseAddr("192.0.2.1")
	ended := netip.MustParseAddr("192.0.2.2")
	exempt := netip.MustParseAddr("192.0.2.3")
	history := []portscan.Detection{
		{Addr: blockedNow, Scan: ev("192.0.2.1", true), Status: portscan.StatusBlocked, LastReported: at},
		{Addr: ended, Scan: ev("192.0.2.2", true), Status: portscan.StatusBlocked, LastReported: at,
			FirstReported: at.Add(-time.Hour)},
		{Addr: exempt, Scan: ev("192.0.2.3", false), Status: portscan.StatusRefused, Reason: "exempt", LastReported: at},
	}
	// Eligibility is judged now, not taken from the record: the exempt
	// source's detection said eligible: false, and is judged so here too.
	eligibleNow := func(ev *portscan.ScanEvent) bool { return ev.BlockEligible }
	out, total := detectionsForUI(history,
		func(a netip.Addr) bool { return a == blockedNow },
		func(a netip.Addr) bool { return a == exempt }, eligibleNow, -1)
	if total != 2 || len(out) != 2 {
		t.Fatalf("got %d of %d, want the 2 not blocked: %+v", len(out), total, out)
	}
	want0 := portscanblocks.Detected{Addr: "192.0.2.2", Method: "tcp-xmas",
		MethodDetail: "TCP Xmas scan (equivalent to nmap -sX)", Status: "ended",
		FirstReported: at.Unix() - 3600, LastReported: at.Unix(), Eligible: true}
	if out[0] != want0 {
		t.Fatalf("a block that ended:\n got %+v\nwant %+v", out[0], want0)
	}
	if out[1].Status != "refused" || out[1].Reason != "exempt" || !out[1].Exempt || out[1].Eligible {
		t.Fatalf("an exempt refusal: %+v", out[1])
	}
	if out, total := detectionsForUI(history, func(netip.Addr) bool { return false },
		func(netip.Addr) bool { return false }, eligibleNow, 1); len(out) != 1 || total != 3 {
		t.Fatalf("limit 1: got %d of %d", len(out), total)
	}
}
