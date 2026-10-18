//go:build linux

package main

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/portscan"
	"github.com/evilsocket/opensnitch/daemon/ui"
	"github.com/evilsocket/opensnitch/daemon/ui/config"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

// These tests drive the daemon's glue -- start, reload, stop -- through the
// real configuration parser and a real Monitor, with only the packet source
// and the firewall replaced. Everything below the glue is tested in
// daemon/portscan; what is tested here is that the daemon calls it with the
// right arguments.

type fakeUI struct {
	mu        sync.Mutex
	warnings  []interface{}
	responder ui.PortScanResponder
}

func (f *fakeUI) SendWarningAlert(data interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.warnings = append(f.warnings, data)
}
func (f *fakeUI) SendPortScanAlert(*protocol.PortScan, bool) {}
func (f *fakeUI) SetPortScanResponder(r ui.PortScanResponder) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responder = r
}

// idleSource is a packet source that never delivers anything.
type idleSource struct {
	once sync.Once
	done chan struct{}
}

func newIdleSource() *idleSource               { return &idleSource{done: make(chan struct{})} }
func (s *idleSource) Run()                     { <-s.done }
func (s *idleSource) Close() error             { s.once.Do(func() { close(s.done) }); return nil }
func (s *idleSource) StartedAt() time.Time     { return time.Now() }
func (s *idleSource) NowNs() uint64            { return uint64(time.Now().UnixNano()) }
func (s *idleSource) Stats() map[string]uint64 { return nil }

// recordingBlocker is a firewall that remembers what it holds.
type recordingBlocker struct {
	mu     sync.Mutex
	held   map[netip.Addr]bool
	closed int
}

func (b *recordingBlocker) Block(a netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.held[a] = true
	return nil
}
func (b *recordingBlocker) Unblock(a netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.held, a)
	return nil
}
func (b *recordingBlocker) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed++
	b.held = map[netip.Addr]bool{}
	return nil
}
func (b *recordingBlocker) holding(a netip.Addr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.held[a]
}

// setupRecorder replaces portScanSetup for one test: it records every
// SetupOptions it is given and builds a Monitor on the fakes above.
type setupRecorder struct {
	mu       sync.Mutex
	calls    []portscan.SetupOptions
	blockers []*recordingBlocker
	// leftover counts the looks for a table left by a previous run.
	leftover int
}

func (r *setupRecorder) setup(opts portscan.SetupOptions) (*portscan.Monitor, string, error) {
	r.mu.Lock()
	r.calls = append(r.calls, opts)
	r.mu.Unlock()
	mopts := portscan.MonitorOptions{
		Config:     opts.Config,
		NeverCount: opts.NeverCount,
		NeverBlock: opts.NeverBlock,
		Report:     opts.Report,
		OnError:    opts.OnError,
		NewSource: func(*portscan.SystemHostInfo, func(*portscan.Probe), func(error)) (portscan.PacketSource, error) {
			return newIdleSource(), nil
		},
	}
	if opts.EnableBlocking {
		mopts.NewBlocker = func(time.Duration) (portscan.Blocker, error) {
			b := &recordingBlocker{held: map[netip.Addr]bool{}}
			r.mu.Lock()
			r.blockers = append(r.blockers, b)
			r.mu.Unlock()
			return b, nil
		}
	}
	m, err := portscan.NewMonitor(mopts)
	return m, "fake", err
}

func withSetupRecorder(t *testing.T) *setupRecorder {
	t.Helper()
	r := &setupRecorder{}
	orig := portScanSetup
	portScanSetup = r.setup
	origLeftover := portScanRemoveLeftoverTable
	portScanRemoveLeftoverTable = func() (bool, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.leftover++
		return true, nil
	}
	t.Cleanup(func() {
		stopPortScanDetection()
		portScanSetup = orig
		portScanRemoveLeftoverTable = origLeftover
		portScanHistory = nil
	})
	return r
}

// TestADaemonThatDoesNotBlockClearsALeftoverTable: only a blocker's setup
// deletes the table of a daemon killed with blocks in force, and a daemon
// that does not block builds none. It must look for that table itself, and
// say when it removes one.
func TestADaemonThatDoesNotBlockClearsALeftoverTable(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{`{"PortScan": {"Enabled": false}}`, 1},
		{`{"PortScan": {"Enabled": true, "Block": {"Policy": "never"}}}`, 1},
		{`{"PortScan": {"Enabled": true, "Block": {"Policy": "ask"}}}`, 0},
	} {
		r := withSetupRecorder(t)
		gui := &fakeUI{}
		startPortScanDetection(parseConfig(t, tc.raw), gui)
		stopPortScanDetection()
		r.mu.Lock()
		got := r.leftover
		r.mu.Unlock()
		if got != tc.want {
			t.Errorf("%s: looked for a leftover table %d times, want %d", tc.raw, got, tc.want)
		}
		gui.mu.Lock()
		said := fmt.Sprint(gui.warnings)
		gui.mu.Unlock()
		if tc.want > 0 && !strings.Contains(said, "previous run") {
			t.Errorf("%s: removing a leftover table was not said: %s", tc.raw, said)
		}
	}
}

func parseConfig(t *testing.T, raw string) *config.Config {
	t.Helper()
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	return &cfg
}

func TestDaemonPassesNeverBlockToSetup(t *testing.T) {
	r := withSetupRecorder(t)
	cfg := parseConfig(t, `{"PortScan": {"Enabled": true,
		"Block": {"Policy": "ask", "NeverBlock": ["192.0.2.0/24"]}}}`)
	startPortScanDetection(cfg, &fakeUI{})

	if len(r.calls) != 1 {
		t.Fatalf("Setup was called %d times, want 1", len(r.calls))
	}
	want := netip.MustParsePrefix("192.0.2.0/24")
	for _, p := range r.calls[0].NeverBlock {
		if p == want {
			return
		}
	}
	t.Fatalf("NeverBlock reached Setup as %v: the operator's %v is blockable",
		r.calls[0].NeverBlock, want)
}

func TestDaemonStopReleasesBlocks(t *testing.T) {
	r := withSetupRecorder(t)
	cfg := parseConfig(t, `{"PortScan": {"Enabled": true, "Block": {"Policy": "ask"}}}`)
	startPortScanDetection(cfg, &fakeUI{})
	if portScanMonitor == nil || len(r.blockers) != 1 {
		t.Fatal("detection did not start with an enforcement backend")
	}
	scanner := netip.MustParseAddr("198.51.100.77")
	portScanMonitor.Readopt([]portscan.BlockedSource{{Addr: scanner, Reason: "test",
		ExpiresAt: time.Now().Add(time.Hour)}})
	if !r.blockers[0].holding(scanner) {
		t.Fatal("the block was not installed; the test does not exercise its case")
	}

	stopPortScanDetection()
	if r.blockers[0].holding(scanner) || r.blockers[0].closed == 0 {
		t.Fatal("stopping detection left the block in the firewall: it would survive" +
			" the daemon until the kernel timeout")
	}
}

func TestReloadRestartsWithoutGraceAndKeepsBlocks(t *testing.T) {
	r := withSetupRecorder(t)
	gui := &fakeUI{}
	startPortScanDetection(parseConfig(t, `{"PortScan": {"Enabled": true,
		"StartupGrace": "1m0s", "Block": {"Policy": "ask"}}}`), gui)
	if len(r.calls) != 1 || r.calls[0].Config.StartupGrace != time.Minute {
		t.Fatalf("the cold start did not arm the grace: %v", r.calls)
	}
	scanner := netip.MustParseAddr("198.51.100.78")
	portScanMonitor.Readopt([]portscan.BlockedSource{{Addr: scanner, Reason: "test",
		ExpiresAt: time.Now().Add(time.Hour)}})

	reloadPortScanDetection(parseConfig(t, `{"PortScan": {"Enabled": true,
		"StartupGrace": "1m0s", "ScoreThreshold": 120, "Block": {"Policy": "ask"}}}`), gui)
	if len(r.calls) != 2 {
		t.Fatalf("a changed threshold made %d Setup calls, want a restart", len(r.calls))
	}
	if g := r.calls[1].Config.StartupGrace; g != 0 {
		t.Fatalf("the restart re-armed a %v grace: every reload would open a blind window", g)
	}
	if !r.blockers[1].holding(scanner) {
		t.Fatal("the block in force was dropped by an unrelated reload")
	}
}

func TestReloadNoticesAModulesPathChange(t *testing.T) {
	r := withSetupRecorder(t)
	gui := &fakeUI{}
	startPortScanDetection(parseConfig(t, `{"PortScan": {"Enabled": true}}`), gui)
	reloadPortScanDetection(parseConfig(t, `{"PortScan": {"Enabled": true}}`), gui)
	if len(r.calls) != 1 {
		t.Fatalf("an unchanged file made %d Setup calls, want 1", len(r.calls))
	}
	reloadPortScanDetection(parseConfig(t, `{"Ebpf": {"ModulesPath": "/opt/mods"},
		"PortScan": {"Enabled": true}}`), gui)
	if len(r.calls) != 2 || r.calls[1].ModulesPath != "/opt/mods" {
		t.Fatalf("an Ebpf.ModulesPath edit was not applied to detection (%d Setup calls)",
			len(r.calls))
	}
}

// TestTheHistorySurvivesTurningDetectionOffAndOn: the sources the user may
// still want to block are kept across a reload, including one that turns
// detection off and then on again.
func TestTheHistorySurvivesTurningDetectionOffAndOn(t *testing.T) {
	withSetupRecorder(t)
	gui := &fakeUI{}
	on := `{"PortScan": {"Enabled": true, "Block": {"Policy": "ask"}}}`
	startPortScanDetection(parseConfig(t, on), gui)
	scanner := netip.MustParseAddr("198.51.100.79")
	portScanMonitor.ReadoptHistory([]portscan.Detection{{Addr: scanner, Status: portscan.StatusIgnored,
		LastReported: time.Now(), FirstReported: time.Now(),
		Scan: &portscan.ScanEvent{Src: scanner, Method: portscan.MethodSYN, HasTCPEvidence: true, BlockEligible: true}}})

	reloadPortScanDetection(parseConfig(t, `{"PortScan": {"Enabled": true, "ScoreThreshold": 120,
		"Block": {"Policy": "ask"}}}`), gui)
	if _, ok := portScanMonitor.Detection(scanner); !ok {
		t.Fatal("a reload forgot the history")
	}
	reloadPortScanDetection(parseConfig(t, `{"PortScan": {"Enabled": false}}`), gui)
	if portScanMonitor != nil {
		t.Fatal("detection still running")
	}
	reloadPortScanDetection(parseConfig(t, on), gui)
	d, ok := portScanMonitor.Detection(scanner)
	if !ok || d.Status != portscan.StatusIgnored {
		t.Fatalf("turning detection off and on lost the history: %+v, %v", d, ok)
	}
	if err := portScanMonitor.ConfirmBlock(scanner); err != nil {
		t.Fatalf("blocking it after: %v", err)
	}
}

// TestTheUISeesEligibilityUnderTheConfigurationInForce: the list and the
// details judge a recorded detection by the configuration in force, as the
// daemon does when asked to block it.
func TestTheUISeesEligibilityUnderTheConfigurationInForce(t *testing.T) {
	withSetupRecorder(t)
	startPortScanDetection(parseConfig(t, `{"PortScan": {"Enabled": true, "Block": {"Policy": "ask"}}}`), &fakeUI{})
	udp := netip.MustParseAddr("198.51.100.80")
	// Recorded eligible, as under RequireTCPEvidence: false; it is true now.
	portScanMonitor.ReadoptHistory([]portscan.Detection{{Addr: udp, Status: portscan.StatusUnanswered,
		LastReported: time.Now(), FirstReported: time.Now(),
		Scan: &portscan.ScanEvent{Src: udp, Method: portscan.MethodUDP, BlockEligible: true}}})
	r := portScanUIResponder{m: portScanMonitor}
	list, _, _ := r.DetectionList(10)
	if len(list) != 1 || list[0].Eligible {
		t.Fatalf("the list says %+v; want not eligible under RequireTCPEvidence", list)
	}
	info, ok := r.BlockInfo(udp)
	if !ok || info.Detection == nil || info.Detection.Eligible {
		t.Fatalf("the details say %+v", info.Detection)
	}
}

// TestAReloadReconcilesTheHistory: a reload that puts a blocked address on
// the never-block list does not leave its entry saying it is blocked. The
// test goes through the reload, where the reconciliation happens.
func TestAReloadReconcilesTheHistory(t *testing.T) {
	withSetupRecorder(t)
	gui := &fakeUI{}
	startPortScanDetection(parseConfig(t, `{"PortScan": {"Enabled": true, "Block": {"Policy": "ask"}}}`), gui)
	a := netip.MustParseAddr("198.51.100.81")
	ev := &portscan.ScanEvent{Src: a, Method: portscan.MethodSYN, HasTCPEvidence: true, BlockEligible: true}
	portScanMonitor.ReadoptHistory([]portscan.Detection{{Addr: a, Status: portscan.StatusBlocked,
		LastReported: time.Now(), FirstReported: time.Now(), Scan: ev}})
	portScanMonitor.Readopt([]portscan.BlockedSource{{Addr: a, Reason: "scan", ExpiresAt: time.Now().Add(time.Hour), Scan: ev}})
	reloadPortScanDetection(parseConfig(t, `{"PortScan": {"Enabled": true,
		"Block": {"Policy": "ask", "NeverBlock": ["198.51.100.0/24"]}}}`), gui)
	d, ok := portScanMonitor.Detection(a)
	if !ok || d.Status != portscan.StatusRefused {
		t.Fatalf("after the reload: %+v, %v; want refused, on the never-block list", d.Status, ok)
	}
}

// TestConcurrentReloadsKeepTheBlocks: the notification loop (CHANGE_CONFIG)
// and the watcher of the configuration file can reload at the same time; a
// reload stepping in between the steps of another would lose the blocks in
// force.
func TestConcurrentReloadsKeepTheBlocks(t *testing.T) {
	// The race is lost about one time in four: twenty rounds make a test
	// that misses it about one time in three hundred.
	for round := 0; round < 20; round++ {
		if !concurrentReloadsKeepTheBlock(t) {
			return
		}
	}
}

func concurrentReloadsKeepTheBlock(t *testing.T) bool {
	t.Helper()
	stopPortScanDetection()
	portScanHistory = nil
	r := withSetupRecorder(t)
	gui := &fakeUI{}
	startPortScanDetection(parseConfig(t, `{"PortScan": {"Enabled": true, "Block": {"Policy": "ask"}}}`), gui)
	scanner := netip.MustParseAddr("198.51.100.78")
	portScanMonitor.Readopt([]portscan.BlockedSource{{Addr: scanner, Reason: "test",
		ExpiresAt: time.Now().Add(time.Hour)}})

	var wg sync.WaitGroup
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				reloadPortScanDetection(parseConfig(t, fmt.Sprintf(`{"PortScan": {"Enabled": true,
					"ScoreThreshold": %d, "Block": {"Policy": "ask"}}}`, 100+g*1000+i)), gui)
			}
		}(g)
	}
	wg.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	open := 0
	for _, b := range r.blockers {
		b.mu.Lock()
		if b.closed == 0 {
			open++
		}
		b.mu.Unlock()
	}
	if open != 1 {
		t.Errorf("%d blockers open after the reloads, want 1", open)
		return false
	}
	if !portScanMonitor.IsBlocked(scanner) || !r.blockers[len(r.blockers)-1].holding(scanner) {
		t.Errorf("the block was lost across concurrent reloads")
		return false
	}
	return true
}

// TestABlockSaysWhenItWasMade: blocked_at lets the user interface list blocks
// and detections together, most recent first; unknown, it is left out rather
// than sent as the epoch.
func TestABlockSaysWhenItWasMade(t *testing.T) {
	now := time.Unix(1760350000, 0)
	b := portscan.BlockedSource{Addr: netip.MustParseAddr("192.0.2.9"),
		ExpiresAt: now.Add(time.Hour), BlockedAt: now.Add(-time.Minute)}
	if got := blockedForUI(b, now).BlockedAt; got != now.Add(-time.Minute).Unix() {
		t.Errorf("blocked_at = %d, want %d", got, now.Add(-time.Minute).Unix())
	}
	b.BlockedAt = time.Time{}
	if got := blockedForUI(b, now).BlockedAt; got != 0 {
		t.Errorf("an unknown block time is sent as %d, want it left out", got)
	}
}
