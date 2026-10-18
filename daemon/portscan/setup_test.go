//go:build linux

package portscan

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// sourceProbe records which constructors were called, so a test can assert not
// only what came up but what was never even attempted.
type sourceProbe struct {
	ebpfCalls int
	afCalls   int
	ebpfErr   error
	afErr     error
	errs      []error
}

func (p *sourceProbe) tryEbpf() (PacketSource, error) {
	p.ebpfCalls++
	if p.ebpfErr != nil {
		return nil, p.ebpfErr
	}
	return newFakeSource(), nil
}

func (p *sourceProbe) tryAFPacket() (PacketSource, error) {
	p.afCalls++
	if p.afErr != nil {
		return nil, p.afErr
	}
	return newFakeSource(), nil
}

func (p *sourceProbe) onError(err error) { p.errs = append(p.errs, err) }

func (p *sourceProbe) run(requested string) (PacketSource, string, error) {
	return selectSource(requested, p.tryEbpf, p.tryAFPacket, p.onError)
}

// ---------------------------------------------------------------------------
// packet source selection
// ---------------------------------------------------------------------------

// TestExplicitEbpfNeverFallsBack is the point of having an explicit selector at
// all.
//
// An operator who writes Source: "ebpf" has made a performance decision. Quietly
// giving them AF_PACKET instead would mean a per-packet cost they did not choose
// and cannot see -- so an unavailable eBPF path is an error, not a fallback.
func TestExplicitEbpfNeverFallsBack(t *testing.T) {
	p := &sourceProbe{ebpfErr: errors.New("no BTF")}

	src, chosen, err := p.run(SourceEbpf)

	if err == nil {
		t.Fatalf("an explicit eBPF request must fail when eBPF is unavailable")
	}
	if !strings.Contains(err.Error(), "no BTF") {
		t.Fatalf("the underlying cause must survive, got %v", err)
	}
	if src != nil || chosen != "" {
		t.Fatalf("no source may be returned on failure, got %v / %q", src, chosen)
	}
	if p.afCalls != 0 {
		t.Fatalf("AF_PACKET was attempted %d times; it must not be", p.afCalls)
	}
}

func TestExplicitEbpfSucceeds(t *testing.T) {
	p := &sourceProbe{}
	src, chosen, err := p.run(SourceEbpf)
	if err != nil || src == nil {
		t.Fatalf("selectSource: %v", err)
	}
	if chosen != SourceEbpf {
		t.Fatalf("chosen = %q, want %q", chosen, SourceEbpf)
	}
	if p.afCalls != 0 {
		t.Fatalf("AF_PACKET must not be built when eBPF came up")
	}
	if len(p.errs) != 0 {
		t.Fatalf("nothing to report when the requested path worked, got %v", p.errs)
	}
}

func TestExplicitAFPacketSkipsEbpfEntirely(t *testing.T) {
	p := &sourceProbe{}
	src, chosen, err := p.run(SourceAFPacket)
	if err != nil || src == nil {
		t.Fatalf("selectSource: %v", err)
	}
	if chosen != SourceAFPacket {
		t.Fatalf("chosen = %q, want %q", chosen, SourceAFPacket)
	}
	if p.ebpfCalls != 0 {
		t.Fatalf("eBPF was attempted %d times despite an explicit AF_PACKET request", p.ebpfCalls)
	}
}

func TestExplicitAFPacketFailurePropagates(t *testing.T) {
	p := &sourceProbe{afErr: errors.New("operation not permitted")}
	if _, _, err := p.run(SourceAFPacket); err == nil ||
		!strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("err = %v, want the AF_PACKET failure", err)
	}
}

func TestAutoPrefersEbpf(t *testing.T) {
	p := &sourceProbe{}
	_, chosen, err := p.run(SourceAuto)
	if err != nil {
		t.Fatalf("selectSource: %v", err)
	}
	if chosen != SourceEbpf {
		t.Fatalf("chosen = %q, want %q", chosen, SourceEbpf)
	}
	if p.afCalls != 0 {
		t.Fatalf("the fallback must not be built when eBPF works")
	}
	if len(p.errs) != 0 {
		t.Fatalf("no notice is owed when the preferred path works, got %v", p.errs)
	}
}

// TestAutoFallsBackAndSaysSo: falling back is allowed under "auto", but it
// changes the per-packet cost, so it is announced.
func TestAutoFallsBackAndSaysSo(t *testing.T) {
	p := &sourceProbe{ebpfErr: ErrEbpfUnavailable}

	_, chosen, err := p.run(SourceAuto)

	if err != nil {
		t.Fatalf("auto must fall back, got %v", err)
	}
	if chosen != SourceAFPacket {
		t.Fatalf("chosen = %q, want %q", chosen, SourceAFPacket)
	}
	if len(p.errs) != 1 {
		t.Fatalf("%d notices reported, want exactly 1", len(p.errs))
	}
	notice := p.errs[0].Error()
	if !strings.Contains(notice, "AF_PACKET") || !strings.Contains(notice, "CPU") {
		t.Fatalf("the notice must name the fallback and its cost, got %q", notice)
	}
	if !IsEbpfUnavailable(p.errs[0]) {
		t.Fatalf("the notice must stay recognisable as an eBPF unavailability")
	}
}

func TestAutoReportsBothFailures(t *testing.T) {
	p := &sourceProbe{
		ebpfErr: errors.New("verifier rejected the program"),
		afErr:   errors.New("CAP_NET_RAW missing"),
	}

	_, chosen, err := p.run(SourceAuto)

	if err == nil {
		t.Fatalf("both sources failed; selectSource must fail")
	}
	for _, want := range []string{"verifier rejected", "CAP_NET_RAW"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, must mention %q", err, want)
		}
	}
	if chosen != "" {
		t.Fatalf("chosen = %q, want empty when nothing came up", chosen)
	}
}

func TestEmptySelectorMeansAuto(t *testing.T) {
	p := &sourceProbe{}
	if _, chosen, err := p.run(""); err != nil || chosen != SourceEbpf {
		t.Fatalf("empty selector: chosen = %q, err = %v", chosen, err)
	}
}

// TestUnknownSelectorIsRefused: a typo must not silently decide which packet
// source runs. This mirrors Config.Validate, which rejects out-of-range values
// rather than clamping them.
func TestUnknownSelectorIsRefused(t *testing.T) {
	p := &sourceProbe{}
	_, _, err := p.run("ebfp")
	if err == nil {
		t.Fatalf("an unknown selector must be refused")
	}
	if !strings.Contains(err.Error(), "ebfp") {
		t.Fatalf("the error must quote what was asked for, got %v", err)
	}
	if p.ebpfCalls != 0 || p.afCalls != 0 {
		t.Fatalf("nothing may be constructed for an unknown selector")
	}
}

// ---------------------------------------------------------------------------
// Setup itself
// ---------------------------------------------------------------------------

// TestSetupRefusesAnInvalidConfiguration proves the validation runs before any
// capability is required, so a misconfiguration is reported as such rather than
// as a permission problem.
func TestSetupRefusesAnInvalidConfiguration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ScoreThreshold = 0

	_, _, err := Setup(SetupOptions{
		Config: cfg,
		Source: SourceAFPacket,
		Report: func(Report) {},
	})
	if err == nil || !strings.Contains(err.Error(), "ScoreThreshold") {
		t.Fatalf("err = %v, want the configuration error", err)
	}
}

func TestSetupRequiresAReportCallback(t *testing.T) {
	_, _, err := Setup(SetupOptions{Config: DefaultConfig(), Source: SourceAFPacket})
	if err == nil || !strings.Contains(err.Error(), "Report callback") {
		t.Fatalf("err = %v, want the missing-callback error", err)
	}
}

func TestSetupRefusesAnUnknownSource(t *testing.T) {
	_, chosen, err := Setup(SetupOptions{
		Config: DefaultConfig(),
		Source: "pcap",
		Report: func(Report) {},
	})
	if err == nil || !strings.Contains(err.Error(), "pcap") {
		t.Fatalf("err = %v, want an unknown-source error", err)
	}
	if chosen != "" {
		t.Fatalf("chosen = %q, want empty", chosen)
	}
}

// TestSetupWithoutPrivilegesFailsCleanly documents what an unprivileged daemon
// gets: an error naming the missing capability, not a panic and not a monitor
// that silently sees nothing.
//
// It is skipped when the tests happen to run as root, where both packet sources
// may legitimately come up.
func TestSetupWithoutPrivilegesFailsCleanly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: both packet sources may legitimately open")
	}

	var notices []error
	m, chosen, err := Setup(SetupOptions{
		Config:  DefaultConfig(),
		Source:  SourceAuto,
		Report:  func(Report) {},
		OnError: func(e error) { notices = append(notices, e) },
	})
	if err == nil {
		if m != nil {
			m.Stop()
		}
		t.Fatalf("an unprivileged Setup unexpectedly succeeded with source %q", chosen)
	}
	if m != nil {
		t.Fatalf("no monitor may be returned alongside an error")
	}
	if chosen != "" {
		t.Fatalf("chosen = %q, want empty when no source came up", chosen)
	}
	// The eBPF failure must have been announced before the fallback was tried,
	// so the log explains why the expensive path was attempted at all.
	if len(notices) == 0 {
		t.Fatalf("the eBPF unavailability was never reported")
	}
}

func TestInterfaceNameForUnknownIndex(t *testing.T) {
	// Index 0 is "no interface"; it must render as something, not panic.
	if got := InterfaceName(0); got == "" {
		t.Logf("InterfaceName(0) = %q", got)
	}
	if got := InterfaceName(1 << 30); got != "" {
		t.Logf("InterfaceName(1<<30) = %q", got)
	}
}

func TestIsEbpfUnavailable(t *testing.T) {
	if !IsEbpfUnavailable(ErrEbpfUnavailable) {
		t.Fatalf("the sentinel must be recognised")
	}
	if IsEbpfUnavailable(errors.New("something else")) {
		t.Fatalf("an unrelated error must not be recognised")
	}
	if IsEbpfUnavailable(nil) {
		t.Fatalf("nil is not an unavailability")
	}
}

// TestAnInterfaceListMatchingNothingIsNotAModuleProblem: with Interfaces naming
// nothing that exists, auto must not announce "the eBPF scan module is
// unavailable ... falling back to AF_PACKET", then fail AF_PACKET on the same
// list. The module is fine; the operator would go looking for a missing file.
func TestAnInterfaceListMatchingNothingIsNotAModuleProblem(t *testing.T) {
	cause := fmt.Errorf("%w: psabsentA, psabsentB", ErrNoConfiguredInterface)
	p := &sourceProbe{ebpfErr: cause, afErr: cause}

	_, _, err := p.run(SourceAuto)
	if !errors.Is(err, ErrNoConfiguredInterface) {
		t.Fatalf("got %v, want the interface list named as the cause", err)
	}
	if IsEbpfUnavailable(err) {
		t.Fatalf("%v reads as the eBPF module being unavailable", err)
	}
	if p.afCalls != 0 {
		t.Fatalf("AF_PACKET was tried %d times on a list that it would refuse too", p.afCalls)
	}
	if len(p.errs) != 0 {
		t.Fatalf("a fallback was announced before the real cause: %v", p.errs)
	}
}
