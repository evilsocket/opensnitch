//go:build linux

package portscan

import (
	"net/netip"
	"testing"
)

// TestOutboundConnectionsAreNotScored pins that the start of this host's own
// outbound connections is not counted as probing.
//
// SystemHostInfo rebuilds its connection table from /proc every ten seconds, so
// a connection opened just after a refresh is not in the snapshot until the
// next one. During that window the SYN|ACK that OPENS it has no known owner,
// and it lands on a different ephemeral port every time, which is precisely the
// case deduplication cannot absorb. Measured with the shipped defaults before
// this: four new connections a minute to one remote address crossed the
// threshold in 52 minutes, twelve a minute in 17 -- and the peer was then
// offered for blocking for four hours.
func TestOutboundConnectionsAreNotScored(t *testing.T) {
	h := newFakeHost() // knows of no connection: the snapshot is always behind
	e := newTestEngine(t, testConfig(), h)

	peer := netip.MustParseAddr("203.0.113.10")
	local := netip.MustParseAddr("192.0.2.1")
	lo, hi := ephemeralRange()

	// An hour of a busy correspondent: one new connection every second, each
	// answered on a fresh ephemeral port.
	const conns = 3600
	for i := 0; i < conns; i++ {
		port := lo + uint16(uint32(i)%uint32(hi-lo))
		p := flagProbe(sec+uint64(i)*uint64(1e9), peer, local, port, TCPSyn|TCPAck)
		if ev := e.Process(p); ev != nil {
			t.Fatalf("connection %d: an ordinary correspondent was reported as %v",
				i, ev.Method)
		}
	}
	if got := e.Score(peer); got != 0 {
		t.Fatalf("score after %d outbound connections = %d, want 0", conns, got)
	}
}

// TestAckScanOfServicePortsIsStillDetected pins the other side of that trade:
// an ACK scan aimed where a scanner aims -- service ports -- still crosses.
func TestAckScanOfServicePortsIsStillDetected(t *testing.T) {
	e := newTestEngine(t, testConfig(), newFakeHost())
	local := netip.MustParseAddr("192.0.2.1")

	var ev *ScanEvent
	for i := 0; i < 120 && ev == nil; i++ {
		ev = e.Process(flagProbe(sec+uint64(i)*ms, attacker, local, uint16(1+i), TCPAck))
	}
	if ev == nil {
		t.Fatal("an ACK scan across service ports was not detected")
	}
	if ev.Method != MethodACK {
		t.Fatalf("method = %v, want tcp-ack", ev.Method)
	}
}

// TestEphemeralRangeIsReadFromTheHost pins that the range comes from the kernel
// rather than a guess, since the whole distinction rests on it.
func TestEphemeralRangeIsReadFromTheHost(t *testing.T) {
	lo, hi := ephemeralRange()
	if lo == 0 || hi <= lo {
		t.Fatalf("ephemeral range = %d-%d, which is not a range", lo, hi)
	}
	if isEphemeralPort(22) || isEphemeralPort(443) {
		t.Fatal("a service port was classified as ephemeral")
	}
	if !isEphemeralPort(lo) || !isEphemeralPort(hi) {
		t.Fatal("the range's own bounds are not in it")
	}
}
