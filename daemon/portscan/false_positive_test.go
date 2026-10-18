//go:build linux

package portscan

import (
	"net/netip"
	"testing"
)

// connHost answers HasConnection for everything, standing in for a peer whose
// traffic this host knows about.
type connHost struct{ *fakeHost }

func (connHost) HasConnection(*Probe) bool { return true }

// TestTunnelPeerIsNotAProtocolScan pins that a peer terminating tunnels with
// this host is not reported as scanning protocols.
//
// The distinct-protocol counter was fed by every accepted packet, including
// those belonging to connections this host already knew about, and protoScan
// crosses without going through the score at all. ESP, AH, GRE, TCP, UDP and
// ICMP are six protocol numbers, so a VPN gateway crossed on six ordinary
// packets and was reported at score 8 against a threshold of 100, with one port
// seen -- an alert with nothing in it the user could act on.
func TestTunnelPeerIsNotAProtocolScan(t *testing.T) {
	h := connHost{newFakeHost()}
	e := newTestEngine(t, testConfig(), h)

	peer := netip.MustParseAddr("203.0.113.20")
	local := netip.MustParseAddr("192.0.2.1")

	// ESP, AH, GRE, TCP, UDP, ICMP: six protocols, all known traffic.
	for i, proto := range []uint8{50, 51, 47, ProtoTCP, ProtoUDP, ProtoICMP} {
		p := &Probe{
			TimeNs: sec + uint64(i)*ms, Src: peer, Dst: local,
			Proto: proto, SrcPort: 4500, DstPort: 4500,
		}
		if ev := e.Process(p); ev != nil {
			t.Fatalf("packet %d (protocol %d): a tunnel peer was reported as %v at score %d",
				i, proto, ev.Method, ev.Score)
		}
	}
}

// TestProtocolScanIsStillDetected pins the other side: unknown traffic across
// several protocols is what nmap -sO looks like and must still cross.
func TestProtocolScanIsStillDetected(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	local := netip.MustParseAddr("192.0.2.1")

	var ev *ScanEvent
	for i, proto := range []uint8{47, 50, 51, 89, 103, 112} {
		p := &Probe{
			TimeNs: sec + uint64(i)*ms, Src: attacker, Dst: local, Proto: proto,
		}
		if got := e.Process(p); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Fatal("an IP protocol scan across six protocols was not detected")
	}
	if ev.Method != MethodProtocol {
		t.Fatalf("method = %v, want ip-protocol", ev.Method)
	}
}

// TestUDPTracerouteIsNotAScan pins that a monitoring station running mtr --udp
// does not produce an alert every cooldown.
//
// UDP traceroute walks its destination port one at a time, so the probes that
// reach the final hop land on a different port every cycle -- a scan's signature
// exactly, and not one. Measured without the exemption: it crossed at the 51st
// port, a little under three minutes, then alerted once per ReportCooldown,
// which is 288 alerts a day from one legitimate station.
func TestUDPTracerouteIsNotAScan(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	local := netip.MustParseAddr("192.0.2.1")

	for i := 0; i <= tracerouteUDPHigh-tracerouteUDPLow; i++ {
		p := udpProbe(sec+uint64(i)*ms, attacker, local, uint16(tracerouteUDPLow+i))
		if ev := e.Process(p); ev != nil {
			t.Fatalf("mtr --udp reported a scan after %d probes: %v", i+1, ev.Method)
		}
	}

	// A TCP scan of the same ports is still detected: the exemption is for the
	// protocol traceroute uses, not for the ports themselves.
	e2 := newTestEngine(t, testConfig(), newFakeHost())
	var ev *ScanEvent
	for i := 0; i < 120 && ev == nil; i++ {
		ev = e2.Process(synProbe(sec+uint64(i)*ms, attacker, local, uint16(tracerouteUDPLow+i)))
	}
	if ev == nil {
		t.Fatal("a TCP scan of the traceroute range was not detected")
	}
}

// TestHighValueServicesAreDetected pins that a sweep of exactly the services an
// attacker wants crosses the threshold.
//
// The port classes weight by IANA range, which is about who registered a number
// rather than what runs there, and the services worth most on a modern machine
// are mostly above 1024. A reconnaissance sweep of exactly those therefore
// scored at the registered weight and stayed under: measured, twelve probes
// covering SSH, RDP, SMB, telnet, FTP, MySQL, PostgreSQL, MSSQL, MS-RPC, VNC
// and Redis produced no alert at all.
func TestHighValueServicesAreDetected(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	local := netip.MustParseAddr("192.0.2.1")

	// Eleven services that matter, in the order a scanner would try them.
	services := []uint16{22, 3389, 445, 23, 21, 3306, 5432, 1433, 135, 5900, 6379}

	var ev *ScanEvent
	for i, port := range services {
		if got := e.Process(synProbe(sec+uint64(i)*ms, attacker, local, port)); got != nil && ev == nil {
			ev = got
		}
	}
	if ev == nil {
		t.Fatalf("a sweep of %d high-value services was not reported; score reached %d"+
			" against a threshold of %d", len(services), e.Score(attacker),
			DefaultScoreThreshold)
	}
}

// TestHighValuePortsAreNotEverything guards the other direction: the list is a
// judgement about a handful of services, not a way to make every registered
// port score like a system one.
func TestHighValuePortsAreNotEverything(t *testing.T) {
	if ClassifyPort(8080) != PortRegistered {
		t.Error("8080 is not a high-value port and must keep its class")
	}
	if ClassifyPort(50000) != PortDynamic {
		t.Error("an ephemeral port must keep its class")
	}
	if ClassifyPort(3389) != PortSystem {
		t.Error("RDP must be weighted as a system port")
	}
	if len(highValuePorts) > 32 {
		t.Errorf("the high-value list has grown to %d entries: at that size the score"+
			" is a service catalogue rather than a signal", len(highValuePorts))
	}
}
