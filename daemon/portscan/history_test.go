//go:build linux

package portscan

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A scan is reconnaissance; the attempt it prepares comes later. The history
// keeps each reported source, and what became of it, so that it can be seen
// and blocked once its alert is gone.

func historyStatusOf(t *testing.T, m *Monitor, addr netip.Addr) DetectionStatus {
	t.Helper()
	d, ok := m.Detection(addr)
	if !ok {
		t.Fatalf("%s is not in the history", addr)
	}
	return d.Status
}

// expireQuestions ages every open question past pendingTTL and runs the
// expiry, as the maintenance loop does once a minute.
func expireQuestions(m *Monitor) {
	m.mu.Lock()
	for a, p := range m.pending {
		p.at = time.Now().Add(-pendingTTL - time.Minute)
		m.pending[a] = p
	}
	m.mu.Unlock()
	m.expirePending()
}

func TestAnUnansweredQuestionCanStillBeBlocked(t *testing.T) {
	h := newTestMonitor(t, nil) // ask
	ev := testScanEvent(attacker)
	h.m.handleEvent(ev)
	if got := historyStatusOf(t, h.m, attacker); got != StatusAsked {
		t.Fatalf("status after the question = %v, want asked", got)
	}
	expireQuestions(h.m)
	if got := historyStatusOf(t, h.m, attacker); got != StatusUnanswered {
		t.Fatalf("status after the question expired = %v, want unanswered", got)
	}
	// The engine never saw this source (the event was handed in directly), as
	// after its state expired: only the history knows it.
	if h.m.engine.LookupForBlock(attacker).Reported {
		t.Fatal("test setup: the engine knows the source")
	}
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("blocking from the history: %v", err)
	}
	src, _, _, ok := h.m.BlockInfo(attacker)
	if !ok || src.Scan != ev || src.Reason != "blocked by the user after the detection" {
		t.Fatalf("block = %+v, %v; want the history's scan and a reason saying how it was made", src, ok)
	}
	if got := historyStatusOf(t, h.m, attacker); got != StatusBlocked {
		t.Fatalf("status after blocking = %v, want blocked", got)
	}
}

func TestAnIgnoredSourceIsKeptAndCanBeBlocked(t *testing.T) {
	h := newTestMonitor(t, nil)
	h.m.handleEvent(testScanEvent(attacker))
	h.m.DismissProposal(attacker)
	if got := historyStatusOf(t, h.m, attacker); got != StatusIgnored {
		t.Fatalf("status after Ignore = %v, want ignored", got)
	}
	list, total := h.m.Detections(10)
	if total != 1 || len(list) != 1 || list[0].Addr != attacker {
		t.Fatalf("Detections = %+v, %d", list, total)
	}
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("blocking an ignored source: %v", err)
	}
}

// TestADismissalOfNothingChangesNothing: an Ignore for a question that is
// not open does not rewrite what became of the source.
func TestADismissalOfNothingChangesNothing(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	h.m.handleEvent(testScanEvent(attacker))
	h.m.DismissProposal(attacker)
	if got := historyStatusOf(t, h.m, attacker); got != StatusBlocked {
		t.Fatalf("status = %v, want blocked", got)
	}
}

func TestANotEligibleDetectionNeedsForce(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	ev := testScanEvent(attacker)
	ev.BlockEligible, ev.HasTCPEvidence = false, false
	h.m.handleEvent(ev)
	d, _ := h.m.Detection(attacker)
	if d.Status != StatusRefused || !strings.Contains(d.Reason, "no corroborating evidence") {
		t.Fatalf("history = %v %q, want refused with the daemon's reason", d.Status, d.Reason)
	}
	if err := h.m.ConfirmBlockForce(attacker, false); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("without force: %v, want ErrNotEligible", err)
	}
	if h.m.IsBlocked(attacker) {
		t.Fatal("blocked without force")
	}
	if err := h.m.ConfirmBlockForce(attacker, true); err != nil {
		t.Fatalf("with force: %v", err)
	}
	src, _, _, _ := h.m.BlockInfo(attacker)
	if !strings.Contains(src.Reason, "not enough to block on its own") {
		t.Fatalf("reason = %q; a forced block must say so", src.Reason)
	}
}

func TestForceNeverOverridesTheNeverBlockList(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	h.m.handleEvent(testScanEvent(neverBlockSrc))
	if got := historyStatusOf(t, h.m, neverBlockSrc); got != StatusRefused {
		t.Fatalf("status = %v, want refused", got)
	}
	if !h.m.IsExempt(neverBlockSrc) {
		t.Fatal("the source is not reported exempt")
	}
	if err := h.m.ConfirmBlockForce(neverBlockSrc, true); !errors.Is(err, ErrExempt) {
		t.Fatalf("forced block of an exempt source: %v, want ErrExempt", err)
	}
}

func TestForceNeverBlocksAnAddressNobodyReported(t *testing.T) {
	h := newTestMonitor(t, nil)
	if err := h.m.ConfirmBlockForce(victim, true); err == nil || !strings.Contains(err.Error(), "never reported") {
		t.Fatalf("forced block of an unreported address: %v", err)
	}
}

func TestAReleaseIsRecorded(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	h.m.handleEvent(testScanEvent(attacker))
	if released, err := h.m.Release(attacker); !released || err != nil {
		t.Fatalf("Release = %v, %v", released, err)
	}
	if got := historyStatusOf(t, h.m, attacker); got != StatusReleased {
		t.Fatalf("status = %v, want released", got)
	}
	// And it can be blocked again, from the history.
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("blocking a released source again: %v", err)
	}
}

func TestUnderPolicyNeverDetectionsAreKeptAndNothingCanBeBlocked(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockNever })
	h.m.handleEvent(testScanEvent(attacker))
	if got := historyStatusOf(t, h.m, attacker); got != StatusDetected {
		t.Fatalf("status = %v, want detected", got)
	}
	if h.m.CanBlock() {
		t.Fatal("CanBlock under the policy never")
	}
	if err := h.m.ConfirmBlock(attacker); err == nil {
		t.Fatal("a block under the policy never")
	}
}

func TestTheHistoryForgetsAfterItsRetention(t *testing.T) {
	h := newTestMonitor(t, nil)
	now := time.Now()
	h.m.history.now = func() time.Time { return now }
	h.m.handleEvent(testScanEvent(attacker))
	h.m.DismissProposal(attacker)

	now = now.Add(HistoryRetention - time.Minute)
	if _, ok := h.m.Detection(attacker); !ok {
		t.Fatal("forgotten before its retention")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := h.m.Detection(attacker); ok {
		t.Fatal("kept past its retention")
	}
	if err := h.m.ConfirmBlock(attacker); err == nil {
		t.Fatal("blocked a source the history has forgotten")
	}
}

func TestTheHistoryIsBounded(t *testing.T) {
	hist := NewHistory()
	now := time.Unix(1700000000, 0)
	hist.now = func() time.Time { return now }
	first := netip.MustParseAddr("10.1.0.0")
	for i := 0; i < MaxHistory+10; i++ {
		now = now.Add(time.Second)
		a := netip.MustParseAddr(fmt.Sprintf("10.1.%d.%d", i/256, i%256))
		hist.Record(testScanEvent(a), StatusDetected, "")
	}
	list, total := hist.List(-1)
	if total != MaxHistory || len(list) != MaxHistory {
		t.Fatalf("history holds %d, want %d", total, MaxHistory)
	}
	// Full of TCP detections: the newest are not kept, the oldest are.
	if _, ok := hist.Lookup(first); !ok {
		t.Fatal("a newer detection pushed out a TCP detection")
	}
	if n := hist.Dropped(); n != 10 {
		t.Fatalf("dropped = %d, want 10", n)
	}
	if !list[0].LastReported.After(list[len(list)-1].LastReported) {
		t.Fatal("not most recent first")
	}
	// Room comes back as entries age out.
	now = now.Add(HistoryRetention)
	hist.Record(testScanEvent(netip.MustParseAddr("10.9.9.9")), StatusDetected, "")
	if _, ok := hist.Lookup(netip.MustParseAddr("10.9.9.9")); !ok {
		t.Fatal("a detection was refused after the history aged out")
	}
}

// TestAReloadKeepsTheHistory: a configuration reload rebuilds the monitor;
// the sources it held can still be blocked, and a question the old monitor
// asked is not reported as still open.
func TestAReloadKeepsTheHistory(t *testing.T) {
	old := newTestMonitor(t, nil)
	ev := testScanEvent(attacker)
	old.m.handleEvent(ev)
	held := old.m.History()

	h := newTestMonitor(t, nil)
	h.m.ReadoptHistory(held)
	d, ok := h.m.Detection(attacker)
	if !ok || d.Scan != ev || d.Status != StatusUnanswered {
		t.Fatalf("after a reload: %+v, %v; want the scan, unanswered", d, ok)
	}
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("blocking after a reload: %v", err)
	}
}

// TestForgedDetectionsDoNotEvictAScanner: a scanner that floods the history
// with forged UDP detections, which cost nothing, must not push its own TCP
// scan out of it.
func TestForgedDetectionsDoNotEvictAScanner(t *testing.T) {
	hist := NewHistory()
	now := time.Unix(1700000000, 0)
	hist.now = func() time.Time { return now }
	scanner := netip.MustParseAddr("198.51.100.66")
	hist.Record(testScanEvent(scanner), StatusUnanswered, "")
	for i := 0; i < 2*MaxHistory; i++ {
		now = now.Add(time.Second)
		ev := testScanEvent(netip.MustParseAddr(fmt.Sprintf("10.2.%d.%d", i/256, i%256)))
		ev.Method, ev.HasTCPEvidence, ev.BlockEligible = MethodUDP, false, false
		hist.Record(ev, StatusRefused, "no corroborating evidence")
	}
	if _, ok := hist.Lookup(scanner); !ok {
		t.Fatal("forged UDP detections evicted the scanner's TCP detection")
	}
	if _, total := hist.List(-1); total != MaxHistory {
		t.Fatalf("history holds %d, want %d", total, MaxHistory)
	}
}

// TestAWeakerDetectionDoesNotRewriteAScanner: UDP from the scanner's own
// address, or forged with it, does not turn its TCP detection into one that
// says its address may be forged.
func TestAWeakerDetectionDoesNotRewriteAScanner(t *testing.T) {
	h := newTestMonitor(t, nil) // ask
	syn := testScanEvent(attacker)
	h.m.handleEvent(syn)
	expireQuestions(h.m)
	udp := testScanEvent(attacker)
	udp.Method, udp.HasTCPEvidence, udp.BlockEligible = MethodMixed, false, false
	h.m.handleEvent(udp)
	d, _ := h.m.Detection(attacker)
	if d.Scan != syn || d.Status != StatusUnanswered {
		t.Fatalf("history = %v %v %q; want the SYN scan, unanswered", d.Scan.Method, d.Status, d.Reason)
	}
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("ConfirmBlock without force: %v", err)
	}
}

// TestEligibilityIsJudgedByTheConfigurationInForce: a detection recorded
// under one configuration is judged by the one in force when the user blocks
// it.
func TestEligibilityIsJudgedByTheConfigurationInForce(t *testing.T) {
	h := newTestMonitor(t, nil)
	weak := testScanEvent(attacker)
	weak.HasTCPEvidence = false // eligible when recorded: RequireTCPEvidence was off
	h.m.history.Record(weak, StatusUnanswered, "")
	h.m.mu.Lock()
	h.m.cfg.Block.RequireTCPEvidence = true
	h.m.mu.Unlock()
	if err := h.m.ConfirmBlockForce(attacker, false); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("a UDP-only detection under RequireTCPEvidence, without force: %v", err)
	}

	// And the other way: recorded under the policy "never", where nothing is
	// eligible, a TCP scan is blockable once the policy allows blocking.
	strong := testScanEvent(victim)
	strong.BlockEligible = false
	h.m.history.Record(strong, StatusDetected, "")
	if err := h.m.ConfirmBlockForce(victim, false); err != nil {
		t.Fatalf("a TCP detection recorded under the policy never: %v", err)
	}
}

// TestRepeatingABlockDoesNotExtendIt.
func TestRepeatingABlockDoesNotExtendIt(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	h.m.handleEvent(testScanEvent(attacker))
	before, _, _, _ := h.m.BlockInfo(attacker)
	time.Sleep(10 * time.Millisecond)
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatalf("ConfirmBlock of a blocked source: %v", err)
	}
	after, _, _, _ := h.m.BlockInfo(attacker)
	if !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatalf("the block was extended: %v -> %v", before.ExpiresAt, after.ExpiresAt)
	}
}

// TestAWeakDetectionOfABlockedSourceIsNotARefusal: a source blocked with
// force and detected again without evidence is still blocked, and neither the
// alert nor the history says the daemon refused.
func TestAWeakDetectionOfABlockedSourceIsNotARefusal(t *testing.T) {
	h := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	first := testScanEvent(attacker)
	h.m.handleEvent(first)
	weak := testScanEvent(attacker)
	weak.HasTCPEvidence, weak.BlockEligible = false, false
	h.m.handleEvent(weak)
	if got := h.last().Outcome; got != OutcomeApplied {
		t.Fatalf("outcome = %v, want applied: the source is blocked", got)
	}
	if got := historyStatusOf(t, h.m, attacker); got != StatusBlocked {
		t.Fatalf("status = %v, want blocked", got)
	}
	if src, _, _, _ := h.m.BlockInfo(attacker); src.Scan != first {
		t.Fatal("the block's details were replaced by a weaker detection")
	}
}

// TestAReloadReconcilesABlockLiftedByTheNeverBlockList.
func TestAReloadReconcilesABlockLiftedByTheNeverBlockList(t *testing.T) {
	old := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	old.m.handleEvent(testScanEvent(neverBlockSrc))
	// Blocked under a configuration where it was not exempt:
	ev := testScanEvent(neverBlockSrc)
	old.m.history.Record(ev, StatusBlocked, "")
	h := newTestMonitor(t, nil)
	h.m.ReadoptHistory(old.m.History())
	h.m.Readopt([]BlockedSource{{Addr: neverBlockSrc, Reason: "scan", ExpiresAt: time.Now().Add(time.Hour), Scan: ev}})
	h.m.ReconcileHistory()
	d, _ := h.m.Detection(neverBlockSrc)
	if d.Status != StatusRefused || !strings.Contains(d.Reason, "never-block") {
		t.Fatalf("status = %v %q; want refused, on the never-block list", d.Status, d.Reason)
	}
}

// TestForgedSYNDetectionsDoNotEvictAScanner: forged SYNs to closed ports
// carry TCP evidence too; a flood of them after a scan must not erase it
// either.
func TestForgedSYNDetectionsDoNotEvictAScanner(t *testing.T) {
	hist := NewHistory()
	now := time.Unix(1700000000, 0)
	hist.now = func() time.Time { return now }
	scanner := netip.MustParseAddr("198.51.100.66")
	hist.Record(testScanEvent(scanner), StatusUnanswered, "")
	for i := 0; i < 2*MaxHistory; i++ {
		now = now.Add(time.Second)
		hist.Record(testScanEvent(netip.MustParseAddr(fmt.Sprintf("10.3.%d.%d", i/256, i%256))), StatusAsked, "")
	}
	if _, ok := hist.Lookup(scanner); !ok {
		t.Fatal("forged SYN detections evicted the scanner")
	}
	if n := hist.Dropped(); n != uint64(2*MaxHistory-(MaxHistory-1)) {
		t.Fatalf("dropped = %d", n)
	}
}

// TestAUserGestureIsNotEvicted: a weak detection the user blocked, or
// released, is not the first to go.
func TestAUserGestureIsNotEvicted(t *testing.T) {
	hist := NewHistory()
	now := time.Unix(1700000000, 0)
	hist.now = func() time.Time { return now }
	forced := testScanEvent(netip.MustParseAddr("198.51.100.67"))
	forced.HasTCPEvidence = false
	hist.Record(forced, StatusBlocked, "")
	for i := 0; i < 2*MaxHistory; i++ {
		now = now.Add(time.Second)
		ev := testScanEvent(netip.MustParseAddr(fmt.Sprintf("10.4.%d.%d", i/256, i%256)))
		ev.HasTCPEvidence = false
		hist.Record(ev, StatusRefused, "")
	}
	if _, ok := hist.Lookup(forced.Src); !ok {
		t.Fatal("a source the user blocked was evicted")
	}
	// Weak detections rotate among themselves: the newest is kept.
	last := netip.MustParseAddr(fmt.Sprintf("10.4.%d.%d", (2*MaxHistory-1)/256, (2*MaxHistory-1)%256))
	if _, ok := hist.Lookup(last); !ok {
		t.Fatal("the newest weak detection was not kept")
	}
}

// TestAKeptDetectionKeepsItsDate: a weaker detection neither refreshes the
// date of the stronger one kept, which would keep it alive and looking new,
// nor hides a question really asked.
func TestAKeptDetectionKeepsItsDate(t *testing.T) {
	hist := NewHistory()
	now := time.Unix(1700000000, 0)
	hist.now = func() time.Time { return now }
	syn := testScanEvent(attacker)
	hist.Record(syn, StatusIgnored, "")
	for i := 0; i < 20; i++ {
		now = now.Add(6 * 24 * time.Hour)
		udp := testScanEvent(attacker)
		udp.HasTCPEvidence = false
		hist.Record(udp, StatusRefused, "no corroborating evidence")
		if i == 0 {
			d, _ := hist.Lookup(attacker)
			if !d.LastReported.Equal(time.Unix(1700000000, 0)) || d.Scan != syn || d.Status != StatusIgnored {
				t.Fatalf("after a weaker detection: %v %v %v", d.LastReported, d.Scan.Method, d.Status)
			}
			hist.Record(udp, StatusAsked, "")
			if d, _ := hist.Lookup(attacker); d.Status != StatusAsked {
				t.Fatalf("a question asked is not recorded: %v", d.Status)
			}
		}
	}
	if d, ok := hist.Lookup(attacker); ok && d.Scan == syn {
		t.Fatal("weak detections kept a TCP accusation alive past its retention")
	}
}

// TestStatusFollowsTheFirewallUnderConcurrentRequests: a block and a release
// of one address at once leave the history saying what the firewall does.
func TestStatusFollowsTheFirewallUnderConcurrentRequests(t *testing.T) {
	h := newTestMonitor(t, nil)
	h.m.handleEvent(testScanEvent(attacker))
	expireQuestions(h.m)
	for i := 0; i < 2000; i++ {
		if err := h.m.ConfirmBlock(attacker); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _, _ = h.m.Release(attacker); close(done) }()
		_ = h.m.ConfirmBlock(attacker)
		<-done
		d, _ := h.m.Detection(attacker)
		if blocked := h.m.IsBlocked(attacker); blocked != (d.Status == StatusBlocked) {
			t.Fatalf("round %d: blocked=%v, history says %v", i, blocked, d.Status)
		}
		_, _ = h.m.Release(attacker)
	}
}

// gatedBlocker holds every Block until the gate opens.
type gatedBlocker struct {
	*fakeBlocker
	gate chan struct{}
}

func (g *gatedBlocker) Block(a netip.Addr) error {
	<-g.gate
	return g.fakeBlocker.Block(a)
}

// TestStopAndHandOverKeepsWhatStopHandled: the history handed to the next
// monitor includes the detections Stop handled from the queue.
func TestStopAndHandOverKeepsWhatStopHandled(t *testing.T) {
	gb := &gatedBlocker{fakeBlocker: newFakeBlocker(), gate: make(chan struct{})}
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
		o.NewBlocker = func(time.Duration) (Blocker, error) { return gb, nil }
	})
	h.m.Start()
	h.m.events <- testScanEvent(attacker)
	got := make(chan []Detection)
	go func() { got <- h.m.StopAndHandOver().History }()
	time.Sleep(100 * time.Millisecond)
	close(gb.gate)
	for _, d := range <-got {
		if d.Addr == attacker {
			return
		}
	}
	t.Fatal("a detection Stop handled is missing from the history handed over")
}

// TestAnAnswerRacingTheQuestionIsNotOverwritten: the user can answer a
// question while the detection that asked it is still being recorded; the
// history must not end up saying "asked" for a source that is blocked.
func TestAnAnswerRacingTheQuestionIsNotOverwritten(t *testing.T) {
	for i := 0; i < 300; i++ {
		h := newTestMonitor(t, nil)
		ev := testScanEvent(attacker)
		done := make(chan struct{})
		go func() { h.m.handleEvent(ev); close(done) }()
		for h.m.ConfirmBlock(attacker) != nil {
			select {
			case <-done:
				_ = h.m.ConfirmBlock(attacker)
			default:
			}
			if h.m.IsBlocked(attacker) {
				break
			}
		}
		<-done
		d, _ := h.m.Detection(attacker)
		if h.m.IsBlocked(attacker) && d.Status != StatusBlocked {
			t.Fatalf("round %d: blocked, history says %v", i, d.Status)
		}
	}
}

// TestABlockAndAReleaseAtOnceAgreeWithTheFirewall holds open the window
// between installing a block and recording it, and releases the address in
// it: the release must wait, or the history ends up saying "blocked" for an
// address the firewall accepts. Deterministic, not a stress test.
func TestABlockAndAReleaseAtOnceAgreeWithTheFirewall(t *testing.T) {
	h := newTestMonitor(t, nil)
	h.m.handleEvent(testScanEvent(attacker))
	expireQuestions(h.m)
	released := make(chan struct{})
	h.m.afterApply = func() {
		go func() { _, _ = h.m.Release(attacker); close(released) }()
		select {
		case <-released:
		case <-time.After(200 * time.Millisecond):
		}
	}
	if err := h.m.ConfirmBlock(attacker); err != nil {
		t.Fatal(err)
	}
	<-released
	d, _ := h.m.Detection(attacker)
	if blocked := h.m.IsBlocked(attacker); blocked != (d.Status == StatusBlocked) {
		t.Fatalf("blocked=%v, history says %v", blocked, d.Status)
	}
}

// TestTheHistoryFullWarningCountsEverything: the warning is paced to once an
// hour; the number it gives is every detection not kept since the last one,
// not the last minute's.
func TestTheHistoryFullWarningCountsEverything(t *testing.T) {
	h := newTestMonitor(t, nil)
	clock := time.Unix(1700000000, 0)
	h.m.now = func() time.Time { return clock }
	h.m.history.now = func() time.Time { return clock }
	for i := 0; i < MaxHistory; i++ {
		h.m.history.Record(testScanEvent(netip.MustParseAddr(fmt.Sprintf("10.5.%d.%d", i/256, i%256))), StatusDetected, "")
	}
	extra := 0
	record := func(n int) {
		for i := 0; i < n; i++ {
			extra++
			h.m.history.Record(testScanEvent(netip.MustParseAddr(fmt.Sprintf("10.6.%d.%d", extra/256, extra%256))), StatusDetected, "")
		}
	}
	warnings := func() []string {
		h.mu.Lock()
		defer h.mu.Unlock()
		var out []string
		for _, e := range h.errs {
			if strings.Contains(e.Error(), "not kept in the detection history") {
				out = append(out, e.Error())
			}
		}
		return out
	}
	record(3)
	h.m.checkHistoryFull()
	for minute := 0; minute < 75; minute++ {
		clock = clock.Add(time.Minute)
		record(3)
		h.m.checkHistoryFull()
	}
	// 3 at once; 30 when it has grown tenfold (minute 10); then, an hour
	// later (minute 70), the 180 not kept since. A count reset every minute
	// would have said 3, then 3.
	var got []int
	for _, w := range warnings() {
		var n int
		i := strings.Index(w, " port scan detections")
		fmt.Sscanf(w[strings.LastIndex(w[:i], " ")+1:i], "%d", &n)
		got = append(got, n)
	}
	if fmt.Sprint(got) != "[3 30 180]" {
		t.Fatalf("warning counts %v, want [3 30 180]", got)
	}
}

// TestEvictionPicksTheOldestUnactedWeakDetection: of the detections without
// TCP evidence, the oldest goes, and one the user released does not.
func TestEvictionPicksTheOldestUnactedWeakDetection(t *testing.T) {
	hist := NewHistory()
	now := time.Unix(1700000000, 0)
	hist.now = func() time.Time { return now }
	weak := func(a string, st DetectionStatus) netip.Addr {
		now = now.Add(time.Second)
		ev := testScanEvent(netip.MustParseAddr(a))
		ev.HasTCPEvidence = false
		hist.Record(ev, st, "")
		return ev.Src
	}
	released := weak("192.0.2.1", StatusReleased)
	oldest := weak("192.0.2.2", StatusRefused)
	newer := weak("192.0.2.3", StatusRefused)
	for i := 0; len(hist.entries) < MaxHistory; i++ {
		now = now.Add(time.Second)
		hist.Record(testScanEvent(netip.MustParseAddr(fmt.Sprintf("10.7.%d.%d", i/256, i%256))), StatusDetected, "")
	}
	weak("192.0.2.4", StatusRefused)
	if _, ok := hist.Lookup(released); !ok {
		t.Fatal("a released detection was evicted")
	}
	if _, ok := hist.Lookup(oldest); ok {
		t.Fatal("the oldest weak detection was kept")
	}
	if _, ok := hist.Lookup(newer); !ok {
		t.Fatal("a newer weak detection was evicted before the oldest")
	}
}

// TestStopAndHandOverReturnsTheBlocksStopMade: under the policy auto, the
// detections Stop handles from the queue can block; the blocks handed to the
// next monitor are read after that, or a reload would drop them.
func TestStopAndHandOverReturnsTheBlocksStopMade(t *testing.T) {
	gb := &gatedBlocker{fakeBlocker: newFakeBlocker(), gate: make(chan struct{})}
	h := newTestMonitor(t, func(o *MonitorOptions) {
		o.Config.Block.Policy = BlockAuto
		o.NewBlocker = func(time.Duration) (Blocker, error) { return gb, nil }
	})
	h.m.Start()
	h.m.events <- testScanEvent(attacker)
	got := make(chan HandOver)
	go func() { got <- h.m.StopAndHandOver() }()
	time.Sleep(100 * time.Millisecond)
	close(gb.gate)
	for _, b := range (<-got).Blocks {
		if b.Addr == attacker {
			return
		}
	}
	t.Fatal("a block Stop made is missing from the blocks handed over")
}

// TestForgetRemovesASourceFromTheList: the user deletes a row of the list. A
// detection goes from the history with its open question, but the engine
// keeps its state, or deleting rows would keep a scanner below the threshold;
// a blocked source is released first, as by Release, which forgets it; a
// source blocked without a history entry is still removed; an address the
// list does not hold is reported as such.
func TestForgetRemovesASourceFromTheList(t *testing.T) {
	h := newTestMonitor(t, nil)
	for i := 0; i < 40; i++ {
		h.probe(uint64(i)*ms, attacker, uint16(20000+i), TCPFin)
	}
	if _, ok := h.m.Detection(attacker); !ok {
		t.Fatal("the detection was not recorded")
	}
	score := h.m.engine.Score(attacker)
	if score == 0 || !h.m.engine.LookupForBlock(attacker).Reported {
		t.Fatal("the engine holds no reported score; the test cannot prove anything")
	}
	if removed, released, err := h.m.Forget(attacker); !removed || released || err != nil {
		t.Fatalf("Forget(detection) = %v, %v, %v", removed, released, err)
	}
	if _, ok := h.m.Detection(attacker); ok {
		t.Error("the deleted detection is still in the history")
	}
	h.m.mu.Lock()
	_, pending := h.m.pending[attacker]
	h.m.mu.Unlock()
	if pending {
		t.Error("the question about the deleted source is still open")
	}
	if h.m.engine.Score(attacker) != score || !h.m.engine.LookupForBlock(attacker).Reported {
		t.Error("deleting a detection forgot the engine's state: a scanner could be kept below the threshold")
	}

	blocked := newTestMonitor(t, func(o *MonitorOptions) { o.Config.Block.Policy = BlockAuto })
	blocked.m.handleEvent(testScanEvent(attacker))
	if !blocked.m.IsBlocked(attacker) {
		t.Fatal("the source was not blocked")
	}
	if removed, released, err := blocked.m.Forget(attacker); !removed || !released || err != nil {
		t.Fatalf("Forget(block) = %v, %v, %v", removed, released, err)
	}
	if blocked.m.IsBlocked(attacker) || blocked.fb.isActive(attacker) {
		t.Error("the deleted source is still blocked")
	}
	if _, ok := blocked.m.Detection(attacker); ok {
		t.Error("the deleted block left its source in the history")
	}

	// Blocked, and no longer in the history: still a row of the list.
	other := netip.MustParseAddr("192.0.2.201")
	blocked.m.handleEvent(testScanEvent(other))
	blocked.m.history.Remove(other)
	if removed, released, err := blocked.m.Forget(other); !removed || !released || err != nil {
		t.Errorf("Forget(block without history) = %v, %v, %v", removed, released, err)
	}

	if removed, _, err := blocked.m.Forget(netip.MustParseAddr("192.0.2.200")); removed || err != nil {
		t.Errorf("Forget(unknown) = %v, %v; want false, nil", removed, err)
	}
}

// TestForgetRefusesOnAStoppedMonitor: during a reload the blocks have already
// been handed to the next monitor; a deletion answered OK there would see
// its block come back.
func TestForgetRefusesOnAStoppedMonitor(t *testing.T) {
	h := newTestMonitor(t, nil)
	h.m.handleEvent(testScanEvent(attacker))
	h.m.Start()
	h.m.StopAndHandOver()
	if removed, _, err := h.m.Forget(attacker); removed || err == nil {
		t.Fatalf("Forget on a stopped monitor = %v, %v; want a refusal", removed, err)
	}
}
