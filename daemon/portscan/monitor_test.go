//go:build linux

package portscan

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// fakeSource is a PacketSource that produces nothing on its own: the test
// injects probes by calling the callback the monitor handed it. Run blocks the
// way a real source does, so Start/Stop exercise the same goroutine handoff.
type fakeSource struct {
	mu      sync.Mutex
	started time.Time
	onProbe func(*Probe)
	onError func(error)

	stop    chan struct{}
	running bool
	runs    int
	closes  int

	// seededAddrs records what the monitor handed the source at construction,
	// and syncedAddrs every later refresh.
	seededAddrs []netip.Addr
	syncedAddrs [][]netip.Addr
	syncErr     error
}

// SyncLocalAddrs makes fakeSource an AddressSink.
func (s *fakeSource) SyncLocalAddrs(addrs []netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncedAddrs = append(s.syncedAddrs, append([]netip.Addr(nil), addrs...))
	return s.syncErr
}

func newFakeSource() *fakeSource {
	return &fakeSource{started: time.Now(), stop: make(chan struct{})}
}

func (s *fakeSource) Run() {
	s.mu.Lock()
	s.runs++
	s.running = true
	s.mu.Unlock()
	<-s.stop
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
}

func (s *fakeSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes++
	if s.closes == 1 {
		close(s.stop)
	}
	return nil
}

func (s *fakeSource) StartedAt() time.Time { return s.started }

// NowNs is in the same clock the test stamps probes from: nanoseconds since the
// source was made, which is what AF_PACKET does.
func (s *fakeSource) NowNs() uint64 { return uint64(time.Since(s.started)) }

func (s *fakeSource) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

// feed injects a probe through the monitor's packet-path callback.
func (s *fakeSource) feed(p *Probe) {
	s.mu.Lock()
	f := s.onProbe
	s.mu.Unlock()
	if f != nil {
		f(p)
	}
}

// exemptPrefix is a documentation range (TEST-NET-2, RFC 5737) used as the
// operator's never-block list. Nothing on a real machine can be in it, so the
// test does not depend on this host's addressing.
const exemptPrefix = "198.51.100.0/24"

var exemptSrc = netip.MustParseAddr("198.51.100.9")

// neverBlockPrefix is blockable-never but still counted: the other half of the
// split between the lists. TEST-NET-3, so nothing real is in it.
const neverBlockPrefix = "203.0.113.0/24"

var neverBlockSrc = netip.MustParseAddr("203.0.113.9")

type monitorHarness struct {
	t   *testing.T
	m   *Monitor
	src *fakeSource
	fb  *fakeBlocker

	mu      sync.Mutex
	reports []Report
	errs    []error
}

func (h *monitorHarness) record(r Report) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reports = append(h.reports, r)
}

func (h *monitorHarness) reportCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.reports)
}

// last returns the most recent report, failing the test if there is none.
func (h *monitorHarness) last() Report {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.reports) == 0 {
		h.t.Fatalf("no report was produced")
	}
	return h.reports[len(h.reports)-1]
}

func (h *monitorHarness) errorTexts() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.errs))
	for _, e := range h.errs {
		out = append(out, e.Error())
	}
	return out
}

// newTestMonitor builds a monitor whose packet source and enforcement backend
// are doubles, over the real SystemHostInfo. The host view is genuine on
// purpose: the exemption checks are the ones that must never be bypassed, and a
// fake host would be testing the double rather than the guard.
func newTestMonitor(t *testing.T, tune func(*MonitorOptions)) *monitorHarness {
	t.Helper()
	h := &monitorHarness{t: t, src: newFakeSource(), fb: newFakeBlocker()}

	cfg := testConfig()
	cfg.Block.Policy = BlockAsk

	opts := MonitorOptions{
		Config:     cfg,
		NeverCount: []netip.Prefix{netip.MustParsePrefix(exemptPrefix)},
		NeverBlock: []netip.Prefix{netip.MustParsePrefix(neverBlockPrefix)},
		Report:     h.record,
		NewBlocker: func(time.Duration) (Blocker, error) {
			return h.fb, nil
		},
		NewSource: func(host *SystemHostInfo, onProbe func(*Probe), onErr func(error)) (PacketSource, error) {
			h.src.mu.Lock()
			h.src.onProbe, h.src.onError = onProbe, onErr
			h.src.seededAddrs = host.LocalAddrs()
			h.src.mu.Unlock()
			return h.src, nil
		},
		OnError: func(err error) {
			h.mu.Lock()
			h.errs = append(h.errs, err)
			h.mu.Unlock()
		},
	}
	if tune != nil {
		tune(&opts)
	}

	m, err := NewMonitor(opts)
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	h.m = m
	t.Cleanup(func() { m.Stop() })
	return h
}

// probe feeds one probe through the monitor's packet-path callback, stamped in
// the source's own clock.
//
// The timestamp must be taken from the source rather than counted from zero:
// the engine's start is read from PacketSource.NowNs, so a probe stamped
// before that falls inside the startup grace and is filtered. Counting from
// zero would make these tests depend on how fast the harness ran, which would
// show up as a failure only under -race.
func (h *monitorHarness) probe(offset uint64, src netip.Addr, port uint16, flags uint8) {
	h.t.Helper()
	p := flagProbe(h.src.NowNs()+offset, src, netip.MustParseAddr("127.0.0.1"), port, flags)
	h.m.onProbe(p)
	h.m.drainEvents()
}

// drainEvents runs everything onProbe queued, synchronously.
//
// onProbe hands a crossing to a goroutine started by Start, because acting on
// it takes a netlink round trip and the packet path must not wait for one (see
// onProbe). These tests drive onProbe directly on a monitor they never start, so
// they run that goroutine's work themselves. Calling this while the monitor IS
// started would race the real loop; no test does both.
func (m *Monitor) drainEvents() {
	for {
		select {
		case ev := <-m.events:
			m.handleEvent(ev)
		default:
			return
		}
	}
}

// testScanEvent is an event that policy would allow blocking: TCP evidence,
// eligible, above threshold.
func testScanEvent(src netip.Addr) *ScanEvent {
	return &ScanEvent{
		Src:            src,
		Method:         MethodSYN,
		MethodDetail:   "tcp-syn",
		DistinctPorts:  12,
		MinPort:        21,
		MaxPort:        443,
		SamplePorts:    []uint16{21, 22, 80, 443},
		Score:          120,
		HasTCPEvidence: true,
		BlockEligible:  true,
		FlagsSummary:   "******S*",
	}
}

// ---------------------------------------------------------------------------
// construction
// ---------------------------------------------------------------------------

// TestMonitorHandsTheHostViewToTheSource guards against the whole feature
// being silently useless on the eBPF path.
//
// The kernel program keeps only packets aimed at one of this host's own
// addresses, consulting a map that userspace fills. If Setup never filled it,
// the map would be empty, so the program would discard every packet -- while
// the daemon reported detection as running. Nothing else in the unit tests
// could see it, because they wire the source by hand and pass the addresses
// themselves.
//
// The source is built from the host view, and this asserts that the view it
// receives is already populated.
func TestMonitorHandsTheHostViewToTheSource(t *testing.T) {
	h := newTestMonitor(t, nil)

	h.src.mu.Lock()
	seeded := h.src.seededAddrs
	h.src.mu.Unlock()

	if len(seeded) == 0 {
		t.Fatalf("the packet source was built with no local addresses: on the eBPF path that means it discards every packet")
	}
	found := false
	for _, a := range seeded {
		if a == netip.MustParseAddr("127.0.0.1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the seeded addresses %v do not include this host's loopback", seeded)
	}
}

// TestMonitorRefreshesTheSourceAddresses: seeding once is not enough. A DHCP
// renewal, a new interface or a rotating IPv6 privacy address changes the set
// while the daemon runs, and a stale kernel map means packets to the new
// address are silently not counted.
func TestMonitorRefreshesTheSourceAddresses(t *testing.T) {
	h := newTestMonitor(t, nil)

	h.m.syncSourceAddrs()

	h.src.mu.Lock()
	synced := h.src.syncedAddrs
	h.src.mu.Unlock()
	if len(synced) != 1 {
		t.Fatalf("%d refreshes recorded, want 1", len(synced))
	}
	if len(synced[0]) == 0 {
		t.Fatalf("the refresh pushed an empty address list")
	}

	// A failing sink is reported, not swallowed: a daemon whose kernel map has
	// gone stale must say so.
	h.src.mu.Lock()
	h.src.syncErr = errors.New("map update failed")
	h.src.mu.Unlock()
	h.m.syncSourceAddrs()
	if errs := h.errorTexts(); len(errs) == 0 ||
		!strings.Contains(errs[len(errs)-1], "map update failed") {
		t.Fatalf("a failed refresh was not reported, got %v", errs)
	}
}

func TestNewMonitorRequiresReportAndSource(t *testing.T) {
	_, err := NewMonitor(MonitorOptions{Config: testConfig()})
	if err == nil || !strings.Contains(err.Error(), "Report callback") {
		t.Fatalf("a missing Report callback must be refused, got %v", err)
	}

	_, err = NewMonitor(MonitorOptions{Config: testConfig(), Report: func(Report) {}})
	if err == nil || !strings.Contains(err.Error(), "packet source") {
		t.Fatalf("a missing packet source must be refused, got %v", err)
	}
}

func TestNewMonitorRejectsInvalidConfig(t *testing.T) {
	cfg := testConfig()
	cfg.ScoreThreshold = 0
	_, err := NewMonitor(MonitorOptions{
		Config:    cfg,
		Report:    func(Report) {},
		NewSource: func(*SystemHostInfo, func(*Probe), func(error)) (PacketSource, error) { return newFakeSource(), nil },
	})
	if err == nil || !strings.Contains(err.Error(), "ScoreThreshold") {
		t.Fatalf("an invalid configuration must be refused, got %v", err)
	}
}

// TestMonitorWithoutBackendDowngradesToNever is the guarantee that the daemon
// never asks a question it could not act on.
//
// Being asked "block this source?" and answering yes, on a daemon with no way
// to enforce it, is worse than not being asked: the user believes they are
// protected. The policy is therefore forced down to "never", loudly.
func TestMonitorWithoutBackendDowngradesToNever(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAsk
		o.NewBlocker = nil
	})

	if got := h.m.Config().Block.Policy; got != BlockNever {
		t.Fatalf("policy = %q, want %q when no enforcement backend exists", got, BlockNever)
	}
	errs := h.errorTexts()
	if len(errs) != 1 || !strings.Contains(errs[0], "blocking disabled") {
		t.Fatalf("the downgrade must be reported, got %v", errs)
	}

	h.m.handleEvent(testScanEvent(attacker))
	if got := h.last().Outcome; got != OutcomeNone {
		t.Fatalf("outcome = %q, want %q", got, OutcomeNone)
	}
	if h.fb.count() != 0 {
		t.Fatalf("nothing must be blocked when there is no backend")
	}
	if h.m.Blocked() != nil {
		t.Fatalf("Blocked() must be empty without a backend")
	}
}

func TestMonitorBackendFailureDowngradesToNever(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
		o.NewBlocker = func(time.Duration) (Blocker, error) {
			return nil, errors.New("nftables is not available")
		}
	})

	if got := h.m.Config().Block.Policy; got != BlockNever {
		t.Fatalf("policy = %q, want %q when the backend cannot be built", got, BlockNever)
	}
	errs := h.errorTexts()
	if len(errs) != 1 || !strings.Contains(errs[0], "nftables is not available") {
		t.Fatalf("the backend's own error must be surfaced, got %v", errs)
	}
}

// TestMonitorConfigReportsEffectiveNotRequested pins the difference between
// what was asked for and what is in force. A status display showing "ask" on a
// daemon that downgraded to "never" would be a lie of the same kind.
func TestMonitorConfigReportsEffectiveNotRequested(t *testing.T) {
	requested := BlockAuto
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = requested
		o.NewBlocker = nil
	})
	if h.m.Config().Block.Policy == requested {
		t.Fatalf("Config() returned the requested policy, not the effective one")
	}
}

// ---------------------------------------------------------------------------
// the block-policy decision, branch by branch
// ---------------------------------------------------------------------------

func TestMonitorPolicyNeverOnlyAlerts(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockNever
	})

	h.m.handleEvent(testScanEvent(attacker))

	r := h.last()
	if r.Outcome != OutcomeNone {
		t.Fatalf("outcome = %q, want %q", r.Outcome, OutcomeNone)
	}
	if r.Reason != "" {
		t.Fatalf("no reason is owed when the policy simply does not block, got %q", r.Reason)
	}
	if h.fb.count() != 0 {
		t.Fatalf("policy never must not touch the firewall")
	}
}

// TestMonitorRefusesUDPOnlyEvidence keeps the cheapest weaponisation of
// automatic blocking closed: a UDP source address costs nothing to forge, so a
// UDP-only accusation must never move a firewall rule.
func TestMonitorRefusesUDPOnlyEvidence(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
	})

	ev := testScanEvent(attacker)
	ev.HasTCPEvidence = false
	ev.BlockEligible = false
	h.m.handleEvent(ev)

	r := h.last()
	if r.Outcome != OutcomeRefused {
		t.Fatalf("outcome = %q, want %q", r.Outcome, OutcomeRefused)
	}
	// The reason must name what is missing, not guess at the cause. "UDP-only
	// evidence" would be a guess: HasTCPEvidence does not mean "TCP arrived",
	// it means a probe only a scanner sends contributed. An event built
	// entirely from ACK-bearing TCP packets has it false, and the operator
	// would read "UDP-only evidence" in the log for a source that had sent no
	// UDP at all.
	if !strings.Contains(r.Reason, "corroborating evidence") {
		t.Fatalf("the reason must name the missing corroboration, got %q", r.Reason)
	}
	if h.fb.count() != 0 {
		t.Fatalf("a UDP-only scan must not install a block")
	}
}

func TestMonitorRefusesIneligibleWithTCPEvidence(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
	})

	ev := testScanEvent(attacker)
	ev.BlockEligible = false // eligibility withheld for some other reason
	h.m.handleEvent(ev)

	r := h.last()
	if r.Outcome != OutcomeRefused {
		t.Fatalf("outcome = %q, want %q", r.Outcome, OutcomeRefused)
	}
	if strings.Contains(r.Reason, "UDP") {
		t.Fatalf("a TCP-backed event must not be refused for a UDP reason, got %q", r.Reason)
	}
	if r.Reason == "" {
		t.Fatalf("a refusal must always carry a reason")
	}
}

// TestMonitorRefusesExemptSource is the anti-self-harm guard at the monitor
// level: an address on the never-block list is refused before any policy runs.
func TestMonitorRefusesExemptSource(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
	})

	h.m.handleEvent(testScanEvent(exemptSrc))

	r := h.last()
	if r.Outcome != OutcomeRefused {
		t.Fatalf("outcome = %q, want %q", r.Outcome, OutcomeRefused)
	}
	if !strings.Contains(r.Reason, "never-block") {
		t.Fatalf("the reason must say the source is exempt, got %q", r.Reason)
	}
	if h.fb.count() != 0 {
		t.Fatalf("an exempt source must never reach the firewall")
	}
}

// TestMonitorExemptCheckPrecedesAskToo: under "ask", an exempt source must not
// even be proposed. Presenting a question whose only sound answer is "no" trains
// the user to accept.
func TestMonitorExemptCheckPrecedesAskToo(t *testing.T) {
	h := newTestMonitor(t, nil) // default policy is ask

	h.m.handleEvent(testScanEvent(exemptSrc))

	if got := h.last().Outcome; got != OutcomeRefused {
		t.Fatalf("outcome = %q, want %q", got, OutcomeRefused)
	}
	h.m.mu.Lock()
	_, pending := h.m.pending[exemptSrc]
	h.m.mu.Unlock()
	if pending {
		t.Fatalf("an exempt source must not be left pending a user answer")
	}
}

func TestMonitorAutoPolicyBlocks(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
	})

	h.m.handleEvent(testScanEvent(attacker))

	r := h.last()
	if r.Outcome != OutcomeApplied {
		t.Fatalf("outcome = %q, want %q", r.Outcome, OutcomeApplied)
	}
	if r.BlockDuration != DefaultBlockDuration {
		t.Fatalf("BlockDuration = %v, want %v", r.BlockDuration, DefaultBlockDuration)
	}
	if !h.fb.isActive(attacker) {
		t.Fatalf("the firewall backend was not asked to block %s", attacker)
	}
	blocked := h.m.Blocked()
	if len(blocked) != 1 || blocked[0].Addr != attacker {
		t.Fatalf("Blocked() = %v, want one entry for %s", blocked, attacker)
	}
}

func TestMonitorAutoPolicySurfacesBackendFailure(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
	})
	h.fb.failNext = errors.New("nft: permission denied")

	h.m.handleEvent(testScanEvent(attacker))

	r := h.last()
	if r.Outcome != OutcomeRefused {
		t.Fatalf("outcome = %q, want %q when the backend fails", r.Outcome, OutcomeRefused)
	}
	if !strings.Contains(r.Reason, "permission denied") {
		t.Fatalf("the backend's error must reach the user, got %q", r.Reason)
	}
}

// TestMonitorAlreadyBlockedDoesNotReinstall: a scan that carries on after the
// block is in place must be reported as blocked, without a second rule.
func TestMonitorAlreadyBlockedDoesNotReinstall(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
	})

	h.m.handleEvent(testScanEvent(attacker))
	h.m.handleEvent(testScanEvent(attacker))

	if got := h.last().Outcome; got != OutcomeApplied {
		t.Fatalf("outcome = %q, want %q", got, OutcomeApplied)
	}
	h.fb.mu.Lock()
	blocks := h.fb.blocks
	h.fb.mu.Unlock()
	if blocks != 1 {
		t.Fatalf("the backend was called %d times, want 1", blocks)
	}
}

func TestMonitorAskPolicyProposes(t *testing.T) {
	h := newTestMonitor(t, nil)

	h.m.handleEvent(testScanEvent(attacker))

	r := h.last()
	if r.Outcome != OutcomeProposed {
		t.Fatalf("outcome = %q, want %q", r.Outcome, OutcomeProposed)
	}
	if h.fb.count() != 0 {
		t.Fatalf("nothing may be blocked before the user answers")
	}
	h.m.mu.Lock()
	_, pending := h.m.pending[attacker]
	h.m.mu.Unlock()
	if !pending {
		t.Fatalf("the proposal must be recorded so a late answer is still honoured")
	}
}

// TestMonitorAskDoesNotRestartTheClock: a scan lasting several minutes must not
// keep resetting the deadline of the question already asked, or the prompt would
// never expire.
func TestMonitorAskDoesNotRestartTheClock(t *testing.T) {
	h := newTestMonitor(t, nil)

	h.m.handleEvent(testScanEvent(attacker))
	h.m.mu.Lock()
	first := h.m.pending[attacker]
	h.m.mu.Unlock()

	time.Sleep(2 * time.Millisecond)
	h.m.handleEvent(testScanEvent(attacker))

	h.m.mu.Lock()
	second := h.m.pending[attacker]
	pendingCount := len(h.m.pending)
	h.m.mu.Unlock()

	if !second.at.Equal(first.at) {
		t.Fatalf("the pending deadline moved: %v -> %v", first.at, second.at)
	}
	if pendingCount != 1 {
		t.Fatalf("%d pending entries, want 1", pendingCount)
	}
	if h.reportCount() != 2 {
		t.Fatalf("both detections must still be reported, got %d", h.reportCount())
	}
}

func TestMonitorExpirePendingDropsStalePrompts(t *testing.T) {
	h := newTestMonitor(t, nil)

	h.m.handleEvent(testScanEvent(attacker))
	h.m.mu.Lock()
	h.m.pending[attacker] = proposal{at: time.Now().Add(-pendingTTL - time.Second)}
	h.m.pending[victim] = proposal{at: time.Now()}
	h.m.mu.Unlock()

	h.m.expirePending()

	h.m.mu.Lock()
	_, stale := h.m.pending[attacker]
	_, fresh := h.m.pending[victim]
	h.m.mu.Unlock()
	if stale {
		t.Fatalf("a prompt older than %v must be dropped", pendingTTL)
	}
	if !fresh {
		t.Fatalf("a fresh prompt must be kept")
	}
}

// ---------------------------------------------------------------------------
// answers coming back from the user interface
// ---------------------------------------------------------------------------

func TestMonitorConfirmBlockInstallsTheRule(t *testing.T) {
	h := newTestMonitor(t, nil)
	h.m.handleEvent(testScanEvent(attacker))

	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("ConfirmBlock: %v", err)
	}
	if !h.fb.isActive(attacker) {
		t.Fatalf("accepting the proposal must install the block")
	}
	h.m.mu.Lock()
	_, stillPending := h.m.pending[attacker]
	h.m.mu.Unlock()
	if stillPending {
		t.Fatalf("an answered proposal must be cleared")
	}
}

// TestMonitorConfirmBlockRevalidatesExemption is the test that matters most in
// this file.
//
// The confirmation arrives over a socket, from a process the daemon does not
// control. Trusting it would let a compromised or merely buggy client make the
// daemon firewall off its own gateway. The exemption list is therefore checked
// again here, not only when the proposal was made -- and it holds even for an
// address that was never proposed.
func TestMonitorConfirmBlockRevalidatesExemption(t *testing.T) {
	h := newTestMonitor(t, nil)

	err := h.m.ConfirmBlock(exemptSrc)
	if err == nil {
		t.Fatalf("ConfirmBlock accepted an exempt address")
	}
	if !errors.Is(err, ErrExempt) {
		t.Fatalf("error = %v, want it to wrap ErrExempt", err)
	}
	if h.fb.count() != 0 {
		t.Fatalf("an exempt address reached the firewall backend")
	}
}

// TestMonitorConfirmBlockHonoursUnpromptedRequest: the user may act from the
// event log long after the notification is gone. That is honoured -- but only
// for a source the engine has actually seen, which is what "acting from the
// event log" means.
//
// Without that check, PORTSCAN_BLOCK would be a primitive for installing a
// drop rule against ANY address, with no detection required, reachable by
// anything that can speak on the notification socket.
func TestMonitorConfirmBlockHonoursUnpromptedRequest(t *testing.T) {
	h := newTestMonitor(t, nil)

	// Never seen: refused, and nothing reaches the firewall.
	if err := h.m.ConfirmBlock(attacker); err == nil {
		t.Fatalf("an address the engine has never seen was accepted")
	}
	if h.fb.count() != 0 {
		t.Fatalf("an unknown address reached the firewall backend")
	}

	// Reported, then dismissed: honoured. Enough probes to actually cross the
	// threshold, because "acting from the event log" means there was an entry in
	// the log -- and that is what the guard tests, rather than a non-zero
	// score that one forged packet supplies.
	for i := 0; i < 20; i++ {
		h.probe(uint64(i)*ms, attacker, uint16(20000+i), TCPFin)
	}
	if h.reportCount() == 0 {
		t.Fatal("the engine never reported the source; this test is not exercising the case it exists for")
	}
	h.m.DismissProposal(attacker)
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("ConfirmBlock for a seen source: %v", err)
	}
	if !h.fb.isActive(attacker) {
		t.Fatalf("a block requested from the log must still be installed")
	}
}

// TestMonitorConfirmBlockReappliesRequireTCPEvidence: the daemon must not refuse
// to block on UDP-only evidence and then install that block on the next message.
//
// handleEvent applies RequireTCPEvidence and tells the user "UDP-only evidence:
// the source address cannot be corroborated". ConfirmBlock, which handles the
// reply arriving over the UI socket, must re-apply it: testing only
// Score(addr) != 0 would not do, since the raw leaky-bucket score is non-zero
// after a single forged packet of any protocol, for the whole of IdleExpiry.
// Measured end to end without the re-check: outcome=refused, reason="UDP-only
// evidence", then ConfirmBlock returned nil and the firewall dropped the
// address. The cost of making an arbitrary address blockable would be one
// forged datagram plus one message, and the addresses that stayed safe would
// be only the ones on the never-block list -- not a VPN endpoint, a file
// server or an update server.
func TestMonitorConfirmBlockReappliesRequireTCPEvidence(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAsk
		o.Config.Block.RequireTCPEvidence = true
	})

	// A UDP-only source, scored well past the threshold.
	for i := 0; i < 40; i++ {
		p := &Probe{
			TimeNs:  h.src.NowNs() + uint64(i)*ms,
			Src:     attacker,
			Dst:     netip.MustParseAddr("127.0.0.1"),
			Proto:   ProtoUDP,
			SrcPort: 40000,
			DstPort: uint16(1 + i), // system ports: UDP weight is 1, the port class carries the score
		}
		h.m.onProbe(p)
		h.m.drainEvents()
	}
	if h.reportCount() == 0 {
		t.Fatal("the UDP scan was never reported; this test is not exercising the case it exists for")
	}
	rep := h.last()
	if rep.Outcome != OutcomeRefused {
		t.Fatalf("outcome = %q, want %q: the policy is meant to refuse UDP-only evidence",
			rep.Outcome, OutcomeRefused)
	}
	if h.m.engine.Score(attacker) == 0 {
		t.Fatal("the source has no score; the old guard would not even have been reached")
	}

	// The reply arriving over the UI socket must meet the same policy.
	err := h.m.ConfirmBlock(attacker)
	if err == nil {
		t.Fatalf("ConfirmBlock installed a block the daemon had just told the user it"+
			" refused to install (reason: %q)", rep.Reason)
	}
	if h.fb.isActive(attacker) {
		t.Fatal("the firewall is dropping an address refused on UDP-only evidence")
	}
	t.Logf("refused as it should be: %v", err)
}

// TestMonitorConfirmBlockAcceptsAProtocolScan is the other direction of the same
// guard: Score() is zero for a reported IP protocol scan, because protocol
// probes add no score at all, so a guard testing the score would refuse a
// legitimate confirmation for the one technique the engine detects without
// scoring.
func TestMonitorConfirmBlockAcceptsAProtocolScan(t *testing.T) {
	// RequireTCPEvidence off: with it on, the engine refuses a protocol scan on
	// its own merits -- there is no TCP evidence in an nmap -sO by definition --
	// and the guard under test would never be reached.
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.RequireTCPEvidence = false
	})

	for i, proto := range []uint8{47, 50, 51, 89, 103} {
		h.m.onProbe(&Probe{
			TimeNs: h.src.NowNs() + uint64(i)*ms,
			Src:    attacker,
			Dst:    netip.MustParseAddr("127.0.0.1"),
			Proto:  proto,
		})
	}
	h.m.drainEvents()
	if h.reportCount() == 0 {
		t.Fatal("the protocol scan was never reported")
	}
	if got := h.m.engine.Score(attacker); got != 0 {
		t.Fatalf("score = %d; this test needs the zero-score case that broke the old guard", got)
	}

	h.m.DismissProposal(attacker)
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("ConfirmBlock for a reported protocol scan: %v", err)
	}
	if !h.fb.isActive(attacker) {
		t.Fatal("the confirmed block was not installed")
	}
}

func TestMonitorConfirmBlockRefusedWhenPolicyIsNever(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockNever
	})

	err := h.m.ConfirmBlock(attacker)
	if err == nil || !strings.Contains(err.Error(), "disabled by configuration") {
		t.Fatalf("error = %v, want a refusal naming the configuration", err)
	}
	if h.fb.count() != 0 {
		t.Fatalf("blocking is disabled; nothing may be installed")
	}
}

// TestMonitorConfirmBlockAcceptsMappedForm: a client that sends ::ffff:192.0.2.66
// must not be able to install a second, parallel block for the same host.
func TestMonitorConfirmBlockAcceptsMappedForm(t *testing.T) {
	h := newTestMonitor(t, nil)

	// The engine must have REPORTED the source: ConfirmBlock refuses an address
	// no detection ever reported.
	for i := 0; i < 20; i++ {
		h.probe(uint64(i)*ms, attacker, uint16(20000+i), TCPFin)
	}

	mapped := netip.AddrFrom16(attacker.As16())
	if err := h.m.ConfirmBlock(mapped); err != nil {
		t.Fatalf("ConfirmBlock(mapped): %v", err)
	}
	if !h.fb.isActive(attacker) {
		t.Fatalf("the mapped form must resolve to the same block as %s", attacker)
	}
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("ConfirmBlock: %v", err)
	}
	if n := h.fb.count(); n != 1 {
		t.Fatalf("%d blocks active, want 1: the two forms are the same address", n)
	}
}

func TestMonitorDismissProposalClearsPending(t *testing.T) {
	h := newTestMonitor(t, nil)
	h.m.handleEvent(testScanEvent(attacker))

	h.m.DismissProposal(attacker)

	h.m.mu.Lock()
	_, pending := h.m.pending[attacker]
	h.m.mu.Unlock()
	if pending {
		t.Fatalf("a declined proposal must be forgotten")
	}
	if h.fb.count() != 0 {
		t.Fatalf("declining must not block anything")
	}
}

// TestMonitorReleaseBlockForgetsTheScore: without this, the source is one probe
// away from the threshold the moment the block is lifted, and the user's
// decision to release is undone by the next packet.
func TestMonitorReleaseBlockForgetsTheScore(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
	})

	// Drive the engine with real probes so there is a real score to forget.
	for i := 0; i < 40; i++ {
		h.probe(uint64(i)*ms, attacker, uint16(20000+i), TCPFin)
	}
	if h.m.engine.Score(attacker) == 0 {
		t.Fatalf("the engine recorded no score; the test cannot prove anything")
	}
	if !h.fb.isActive(attacker) {
		t.Fatalf("the scan should have been blocked under policy auto")
	}

	if err := h.m.ReleaseBlock(attacker); err != nil {
		t.Fatalf("ReleaseBlock: %v", err)
	}

	if got := h.m.engine.Score(attacker); got != 0 {
		t.Fatalf("score after release = %d, want 0", got)
	}
	if h.fb.isActive(attacker) {
		t.Fatalf("the firewall rule was not removed")
	}
}

func TestMonitorReleaseBlockWithoutBackendIsHarmless(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockNever
	})
	if err := h.m.ReleaseBlock(attacker); err != nil {
		t.Fatalf("ReleaseBlock without a backend: %v", err)
	}
}

// ---------------------------------------------------------------------------
// the packet path and the lifecycle
// ---------------------------------------------------------------------------

// TestMonitorProbeToReportPath exercises the real chain: a probe enters through
// the source callback, the engine judges it, and a report comes out.
func TestMonitorProbeToReportPath(t *testing.T) {
	h := newTestMonitor(t, nil)

	for i := 0; i < 40 && h.reportCount() == 0; i++ {
		h.probe(uint64(i)*ms, attacker, uint16(20000+i), TCPFin)
	}

	r := h.last()
	if r.Event == nil || r.Event.Src != attacker {
		t.Fatalf("report = %+v, want an event from %s", r, attacker)
	}
	if r.Outcome != OutcomeProposed {
		t.Fatalf("outcome = %q, want %q under the default policy", r.Outcome, OutcomeProposed)
	}
	if !r.Event.HasTCPEvidence {
		t.Fatalf("TCP probes must be recorded as TCP evidence")
	}
	st := h.m.Stats()
	if st.ProbesSeen == 0 || st.EventsEmitted != 1 {
		t.Fatalf("stats = %+v, want probes seen and exactly one event", st)
	}
}

// TestMonitorIgnoresProbesBelowThreshold: an ordinary connection attempt must
// not produce a report.
func TestMonitorIgnoresProbesBelowThreshold(t *testing.T) {
	h := newTestMonitor(t, nil)

	local := netip.MustParseAddr("127.0.0.1")
	h.m.onProbe(synProbe(h.src.NowNs()+ms, attacker, local, 22))
	h.m.drainEvents()

	if n := h.reportCount(); n != 0 {
		t.Fatalf("%d reports for a single SYN, want 0", n)
	}
}

func TestMonitorStartStopLifecycle(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
	})

	h.m.Start()
	h.m.Start() // idempotent

	deadline := time.Now().Add(2 * time.Second)
	for {
		h.src.mu.Lock()
		running := h.src.running
		runs := h.src.runs
		h.src.mu.Unlock()
		if running {
			if runs != 1 {
				t.Fatalf("the source was started %d times, want 1", runs)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the packet source never started")
		}
		time.Sleep(time.Millisecond)
	}

	h.src.feed(flagProbe(ms, attacker, netip.MustParseAddr("127.0.0.1"), 20001, TCPFin))

	h.m.Stop()
	h.m.Stop() // idempotent

	if h.src.closeCount() == 0 {
		t.Fatalf("Stop must close the packet source")
	}
}

// TestMonitorStopReleasesEveryBlock: a firewall rule that outlives the process
// that installed it is a rule nobody owns and nobody will remove.
func TestMonitorStopReleasesEveryBlock(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
	})
	h.m.Start()

	h.m.handleEvent(testScanEvent(attacker))
	h.m.handleEvent(testScanEvent(attacker6))
	if h.fb.count() != 2 {
		t.Fatalf("%d blocks installed, want 2", h.fb.count())
	}

	h.m.Stop()

	if n := h.fb.count(); n != 0 {
		t.Fatalf("%d blocks survived shutdown, want 0", n)
	}
}

// TestMonitorConcurrentProbesAndAnswers runs the packet path against the
// control path, which is exactly how the daemon uses this type: one goroutine
// per packet source, another handling messages from the user interface.
func TestMonitorConcurrentProbesAndAnswers(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
	})

	local := netip.MustParseAddr("127.0.0.1")
	base := h.src.NowNs()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			src := netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", 100+w))
			for i := 0; i < 200; i++ {
				h.m.onProbe(flagProbe(base+uint64(i)*ms, src, local, uint16(20000+i), TCPFin))
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = h.m.ConfirmBlock(netip.MustParseAddr("192.0.2.200"))
			_ = h.m.ReleaseBlock(netip.MustParseAddr("192.0.2.200"))
			h.m.DismissProposal(netip.MustParseAddr("192.0.2.201"))
			_ = h.m.Blocked()
			_ = h.m.Stats()
			_ = h.m.Config()
		}
	}()
	wg.Wait()
	// One consumer, as in production: onProbe queues, a single goroutine acts.
	h.m.drainEvents()

	if h.reportCount() == 0 {
		t.Fatalf("no scan was reported under concurrent load")
	}
}

// TestNewMonitorReleasesTheBackendWhenTheSourceFails: a failure after the
// enforcement backend was built must not leave its objects installed.
//
// NewNftBlocker installs the table, the chain in the input hook and the two drop
// rules during construction. The later error paths closed nothing, so the daemon
// logged "port scan detection could not start", kept running, and left two rules
// for every inbound packet on the machine to evaluate for the life of the
// process -- with nothing able to remove them, since the shutdown path returns
// immediately when the monitor is nil.
//
// The path is ordinary: Source "ebpf" configured where opensnitch-scan.o was
// never built, or AF_PACKET refusing because one interface could not be bound.
func TestNewMonitorReleasesTheBackendWhenTheSourceFails(t *testing.T) {
	fb := newFakeBlocker()
	built := 0

	cfg := testConfig()
	cfg.Block.Policy = BlockAsk
	_, err := NewMonitor(MonitorOptions{
		Config: cfg,
		Report: func(Report) {},
		NewBlocker: func(time.Duration) (Blocker, error) {
			built++
			return fb, nil
		},
		NewSource: func(*SystemHostInfo, func(*Probe), func(error)) (PacketSource, error) {
			return nil, errors.New("no packet source is usable on this machine")
		},
		OnError: func(error) {},
	})
	if err == nil {
		t.Fatal("NewMonitor succeeded with no packet source")
	}
	if built != 1 {
		t.Fatalf("the backend was built %d times, want 1", built)
	}
	if fb.closeCount() == 0 {
		t.Fatal("the enforcement backend was constructed and never closed: its table," +
			" its chain in the input hook and its two rules are still installed, and" +
			" nothing in the daemon can remove them")
	}
}

// TestStartAfterStopDoesNotPanic: Stop sets running back to false, so Start's
// guard stopped protecting anything once Stop had run -- a second Start closed
// m.done again. "close of closed channel", raised inside a goroutine where no
// caller's recover can reach it, kills a daemon that runs as root and carries
// the machine's outbound filtering. Nothing calls Start twice today; this is the
// trap that was set for whoever adds configuration reloading.
func TestStartAfterStopDoesNotPanic(t *testing.T) {
	h := newTestMonitor(t, nil)
	h.m.Start()
	h.m.Stop()
	h.m.Start() // must be a no-op, not a panic
	h.m.Stop()  // and must stay idempotent
}

// TestStopWithoutStartStillReleasesEverything: returning early on !running meant
// a monitor built and then stopped released nothing -- the packet source stayed
// open (TCX program attached, ring buffer reader and sockets alive) and the
// nftables table NewMonitor had installed survived with no owner.
func TestStopWithoutStartStillReleasesEverything(t *testing.T) {
	h := newTestMonitor(t, nil)

	h.m.Stop()

	if h.src.closeCount() == 0 {
		t.Error("the packet source was never closed: on the eBPF path the program stays" +
			" attached to every interface and the ring buffer reader stays open")
	}
	if h.fb.closeCount() == 0 {
		t.Error("the enforcement backend was never closed: its table and its two rules" +
			" in the input hook survive with nobody owning them")
	}
}

// TestZeroCooldownMeansNoCooldown: Validate accepts ReportCooldown = 0, and the
// configuration documents it as "how long before the same source is reported
// again" -- which reads naturally as "straight away". A cooldown test that
// zero made always true would mean the exact opposite: a source reported once
// and never again while its entry lived. Measured that way: 4000 probes over
// 600 ports across an hour from one source produced exactly one event.
func TestZeroCooldownMeansNoCooldown(t *testing.T) {
	cfg := testConfig()
	cfg.ReportCooldown = 0
	cfg.AlertsPerMinute = maxAlertsPerMinute
	e := newTestEngine(t, cfg, newFakeHost())

	events := 0
	tNs := uint64(sec)
	for i := 0; i < 600; i++ {
		tNs += ms
		if ev := e.Process(synProbe(tNs, attacker, victim, uint16(1000+i))); ev != nil {
			events++
		}
	}
	if events < 2 {
		t.Errorf("%d events for a 600-port scan with ReportCooldown 0: zero is documented"+
			" as no cooldown, and used to mean one alert for the life of the entry", events)
	}
	t.Logf("%d events emitted with no cooldown", events)
}

// TestReleaseBlockDoesNotEraseEvidenceForAnUnblockedSource pins that
// PORTSCAN_UNBLOCK is not a primitive for erasing any source's score.
//
// A ReleaseBlock that called Engine.Forget unconditionally, for any address,
// whether or not it was ever blocked and whether or not it was ever detected,
// would be exactly that. The message arrives over a socket the daemon does not
// authenticate, so anyone able to reach it could keep a scanner permanently
// below the threshold by sending one release now and then: measured that way,
// one message every eight probes hid 180 probes completely, where nine
// normally suffice to report.
func TestReleaseBlockDoesNotEraseEvidenceForAnUnblockedSource(t *testing.T) {
	h := newTestMonitor(t, nil)

	local := netip.MustParseAddr("127.0.0.1")
	base := h.src.NowNs()
	for i := 0; i < 8; i++ {
		h.m.onProbe(synProbe(base+uint64(i)*ms, attacker, local, uint16(21+i)))
	}
	h.m.drainEvents()
	before := h.m.engine.Score(attacker)
	if before == 0 {
		t.Fatal("the probes scored nothing; this test is not exercising its case")
	}

	// The source was never blocked, so this must not touch its state.
	if err := h.m.ReleaseBlock(attacker); err != nil {
		t.Fatalf("ReleaseBlock: %v", err)
	}
	if got := h.m.engine.Score(attacker); got != before {
		t.Fatalf("score went from %d to %d after releasing a block that never"+
			" existed: detection can be reset at will over an unauthenticated socket",
			before, got)
	}

	// A genuine release still forgets, so letting a source go does not leave it
	// one probe away from being blocked again.
	if err := h.m.ConfirmBlock(attacker); err == nil {
		if err := h.m.ReleaseBlock(attacker); err != nil {
			t.Fatalf("ReleaseBlock after a real block: %v", err)
		}
		if got := h.m.engine.Score(attacker); got != 0 {
			t.Fatalf("score after a genuine release = %d, want 0", got)
		}
	}
}

// runCloseSource records whether Run was ever entered after Close returned.
type runCloseSource struct {
	*fakeSource
	mu            sync.Mutex
	closed        bool
	runAfterClose int
}

func (s *runCloseSource) Run() {
	s.mu.Lock()
	if s.closed {
		s.runAfterClose++
	}
	s.mu.Unlock()
	s.fakeSource.Run()
}

func (s *runCloseSource) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return s.fakeSource.Close()
}

// TestConcurrentStartStopIsSafe pins the lifecycle against a Stop that lands in
// the middle of a Start.
//
// A Start that marked the monitor running, released the lock, and only then
// called host.Start, blocks.Start and launched its goroutines would leave a
// window in which a Stop went straight to source.Close() before Start had
// wired anything, so blocks.Start could run after blocks.Stop and Run could be
// entered on an already-closed source. Measured with such a Start: the first
// of 200 iterations.
//
// Run being entered on a closed source cannot be excluded from the outside --
// Close is the only thing that can wake a blocked Run, so Stop must be free to
// call it at any moment. That is why PacketSource requires Run to tolerate
// it, and why this test checks the two things that CAN be guaranteed: the wiring
// is ordered, and nothing panics or hangs.
func TestConcurrentStartStopIsSafe(t *testing.T) {
	for i := 0; i < 200; i++ {
		var src *runCloseSource
		h := newTestMonitor(t, func(o *MonitorOptions) {
			o.NewSource = func(_ *SystemHostInfo, onProbe func(*Probe), onErr func(error)) (PacketSource, error) {
				src = &runCloseSource{fakeSource: newFakeSource()}
				return src, nil
			}
		})

		done := make(chan struct{})
		go func() {
			defer close(done)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); h.m.Start() }()
			go func() { defer wg.Done(); h.m.Stop() }()
			wg.Wait()
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("iteration %d: Start and Stop deadlocked", i)
		}

		src.mu.Lock()
		closed := src.closed
		src.mu.Unlock()
		if !closed {
			t.Fatalf("iteration %d: the source was never closed", i)
		}
	}
}

// TestPacketSourceRunAfterCloseIsSafe holds the real sources to the contract
// PacketSource states: Run on a closed source returns promptly rather than
// blocking, panicking, or reading from freed state.
//
// It is the half of the lifecycle that cannot be ordered away, so it is the half
// that has to be checked directly.
func TestPacketSourceRunAfterCloseIsSafe(t *testing.T) {
	// On lo, named: the live tests' namespace has no other interface, and
	// with none named the source watches every one but loopback -- so this
	// test would find nothing to open and skip in every harness.
	requireLiveEnv(t)
	src, err := NewAFPacketSource([]string{"lo"}, afPacketDefaultBudget, func(*Probe) {}, func(error) {})
	if err != nil {
		t.Fatalf("NewAFPacketSource on lo: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	done := make(chan struct{})
	go func() { defer close(done); src.Run() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("AFPacketSource.Run did not return when called on a closed source")
	}
}

// TestConfirmBlockRefusesATrackedButUnreportedSource: the user interface may
// only confirm a block the engine proposed. Without the check, one SYN made any
// address blockable from the UI socket, and no test noticed its removal.
func TestConfirmBlockRefusesATrackedButUnreportedSource(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAsk
		o.Config.Block.RequireTCPEvidence = true
	})
	h.probe(0, attacker, 22, TCPSyn) // one SYN: tracked, TCP evidence, far below threshold
	if h.reportCount() != 0 || h.m.engine.Score(attacker) == 0 {
		t.Fatalf("precondition: want a tracked, unreported source (reports=%d score=%d);"+
			" the test does not exercise its case", h.reportCount(), h.m.engine.Score(attacker))
	}
	if err := h.m.ConfirmBlock(attacker); err == nil || h.fb.isActive(attacker) {
		t.Fatalf("ConfirmBlock blocked a source no detection ever reported (err=%v)", err)
	}
}

// TestAReleaseIsNotUndoneByAQueuedCrossing: under the policy auto, a blocked
// source that crossed again while the alert limiter was full waits in the
// report queue; the user's release must take it out, or the next drain blocks
// the source again with no packet from it since.
func TestAReleaseIsNotUndoneByAQueuedCrossing(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
		o.Config.AlertsPerMinute = 3
	})
	local := netip.MustParseAddr("127.0.0.1")
	x := netip.MustParseAddr("192.0.2.77")
	base := h.src.NowNs() + 10*sec
	scan := func(at uint64, src netip.Addr, first uint16) {
		for k := uint16(0); k < 40; k++ {
			h.m.onProbe(flagProbe(at+uint64(k)*ms, src, local, first+k, TCPSyn))
			h.m.drainEvents()
		}
	}
	scan(base, x, 600)
	if !h.fb.isActive(x) {
		t.Fatalf("x was not blocked; reports=%d", h.reportCount())
	}
	// Past the cooldown, three other sources fill the limiter's window, then
	// x shows new ports and is queued.
	t1 := base + 6*60*sec
	for d := 0; d < 3; d++ {
		scan(t1+uint64(d)*sec, netip.AddrFrom4([4]byte{192, 0, 2, byte(100 + d)}), 600)
	}
	before := h.reportCount()
	scan(t1+10*sec, x, 700)
	if h.reportCount() != before {
		t.Fatalf("x was reported at once; the limiter did not queue it")
	}
	if released, err := h.m.Release(x); !released || err != nil {
		t.Fatalf("Release(x) = %v, %v", released, err)
	}
	h.m.drainPendingReports(t1 + 75*sec)
	h.m.drainEvents()
	if h.fb.isActive(x) {
		t.Fatalf("x, released by the user, was blocked again by a crossing queued before the release")
	}
}
