//go:build linux

package portscan

import (
	"errors"
	"net/netip"
	"testing"
)

// TestEmptyHostViewDetectsNothing states the consequence plainly, so that the
// guards around it are never mistaken for belt and braces.
//
// Engine.accept counts only packets aimed at one of this host's own unicast
// addresses. With none, every packet is discarded before it is even counted:
// ProbesSeen stays at zero, so a blind detector is indistinguishable from a
// quiet network by any counter the daemon exposes.
func TestEmptyHostViewDetectsNothing(t *testing.T) {
	h := newFakeHost()
	h.allLocal = false // knows of no local address at all

	e := newTestEngine(t, testConfig(), h)
	for i := 0; i < 500; i++ {
		e.Process(synProbe(sec+uint64(i)*ms, attacker,
			netip.MustParseAddr("192.0.2.1"), uint16(1+i)))
	}

	st := e.Stats()
	if st.EventsEmitted != 0 {
		t.Fatalf("an engine with no local addresses reported %d event(s)", st.EventsEmitted)
	}
	if st.ProbesSeen != 0 && st.ProbesCounted != 0 {
		t.Fatalf("stats unexpectedly non-zero: %+v", st)
	}
	t.Logf("500 probes against an empty host view: %+v", st)
}

// TestHostAddressFailureIsFatal pins that an unreadable interface list stops the
// monitor being built, rather than being filed as an infrastructure problem.
//
// NewSystemHostInfo's comment claimed this return existed. It did not: the error
// went into infraErr, whose documentation says it means "the never-block list
// may be incomplete", so NewMonitor reported that unrelated message and built a
// detector that could not see anything. The distinguishing wrapper is what this
// checks, since the fatal path depends on it.
func TestHostAddressFailureIsFatal(t *testing.T) {
	wrapped := errors.Join(ErrHostAddresses, errors.New("ENOBUFS"))
	if !errors.Is(wrapped, ErrHostAddresses) {
		t.Fatal("ErrHostAddresses does not survive wrapping; the fatal path cannot see it")
	}

	// An infrastructure error must NOT be mistaken for it, or a broken
	// resolv.conf would stop the daemon -- handing anything that can write that
	// file a way to switch detection off.
	infra := errors.New("portscan: reading /etc/resolv.conf: permission denied")
	if errors.Is(infra, ErrHostAddresses) {
		t.Fatal("an infrastructure error matches ErrHostAddresses: a broken resolv.conf" +
			" would become fatal")
	}
}
