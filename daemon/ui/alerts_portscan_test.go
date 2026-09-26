package ui

import (
	"strings"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"google.golang.org/protobuf/proto"
)

// TestAPortScanAlertCarriesTextForAnOlderGUI: a GUI that predates the PortScan
// message reads only the oneof. If the oneof held the PortScan and nothing
// else, such a GUI would show every scan as a notification with an empty body
// -- critical, when it proposed a block, with no way to answer it. The
// structured payload sits beside the oneof, and the oneof carries a summary.
func TestAPortScanAlertCarriesTextForAnOlderGUI(t *testing.T) {
	scan := &protocol.PortScan{SrcIp: "203.0.113.9", Interface: "eth0",
		Method: "TCP SYN scan", DistinctPorts: 120, MinPort: 1, MaxPort: 1024,
		BlockEligible: true}
	for _, proposed := range []bool{false, true} {
		prio := protocol.Alert_MEDIUM
		if proposed {
			prio = protocol.Alert_HIGH
		}
		a := NewAlert(protocol.Alert_WARNING, protocol.Alert_PORT_SCAN,
			protocol.Alert_SHOW_ALERT, prio, scan)
		raw, err := proto.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		var back protocol.Alert
		if err := proto.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		if back.GetPortscan().GetSrcIp() != "203.0.113.9" {
			t.Fatal("the structured payload did not survive the wire")
		}
		text := back.GetText()
		for _, want := range []string{"203.0.113.9", "eth0", "TCP SYN scan", "120 ports"} {
			if !strings.Contains(text, want) {
				t.Errorf("the summary %q does not name %q", text, want)
			}
		}
		if proposed != strings.Contains(text, "Blocking") {
			t.Errorf("proposed=%v but the summary is %q", proposed, text)
		}
	}
}
