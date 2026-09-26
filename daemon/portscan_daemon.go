//go:build linux

package main

import (
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/portscan"
	"github.com/evilsocket/opensnitch/daemon/tasks/portscanblocks"
	"github.com/evilsocket/opensnitch/daemon/ui"
	"github.com/evilsocket/opensnitch/daemon/ui/config"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

// portScanUI is what detection needs from the user interface client, an
// interface so this glue can be tested without a UI socket.
type portScanUI interface {
	SendWarningAlert(data interface{})
	SendPortScanAlert(scan *protocol.PortScan, needsAnswer bool)
	SetPortScanResponder(r ui.PortScanResponder)
}

// portScanSetup is portscan.Setup, replaced by the tests.
var portScanSetup = portscan.Setup

// portScanRemoveLeftoverTable is portscan.RemoveLeftoverTable, replaced by the
// tests.
var portScanRemoveLeftoverTable = portscan.RemoveLeftoverTable

// removeLeftoverBlocks deletes the nftables table of a daemon that died with
// blocks in force, when this one will not build a blocker to do it. Without
// it, the blocks would go on dropping traffic while the list says nothing is
// blocked.
func removeLeftoverBlocks(client portScanUI) {
	removed, err := portScanRemoveLeftoverTable()
	if err != nil {
		// No nf_tables, or no privilege: then there is no table either.
		log.Debug("[port scan] looking for a table left by a previous run: %v", err)
		return
	}
	if removed {
		msg := "Port scan detection: removed the blocks left in the firewall by a previous run that did not stop cleanly"
		log.Warning("[port scan] %s", msg)
		client.SendWarningAlert(msg)
	}
}

var (
	// portScanLifecycleMu serialises start, stop and reload end to end. They
	// are reached from the notification loop (CHANGE_CONFIG), the watcher of
	// the configuration file and shutdown; portScanMu alone is released
	// between the steps of a reload, and a second reload taking a step in
	// between would lose the blocks in force. Taken before portScanMu.
	portScanLifecycleMu sync.Mutex
	portScanMu          sync.Mutex
	portScanMonitor     *portscan.Monitor
	// portScanRequested is the configuration the file asked for, so a reload can
	// tell a real edit from a rewrite of the same content. Not Monitor.Config(),
	// the effective configuration, which Setup downgrades when no enforcement
	// backend can be built: compared with the request, it would differ on every
	// such machine and every write of the file would rebuild detection.
	portScanRequested portScanRequest
	// portScanClient is kept so the responder can be unregistered on shutdown.
	portScanClient portScanUI
	// portScanHistory is the detection history of the last monitor stopped,
	// taken over by the next one: a reload rebuilds the monitor, and turning
	// detection off and on again is no reason to forget the sources the user
	// may still want to block. It lives in memory; a daemon restart starts
	// it empty.
	portScanHistory []portscan.Detection
)

// portScanRequest is everything the configuration file asked for, which is more
// than portscan.Config holds: NeverBlock, NeverCount, Source and
// Ebpf.ModulesPath travel apart from it, and a reload must see an edit to any
// of them -- NeverBlock above all, the list an operator edits after their
// gateway was blocked.
type portScanRequest struct {
	cfg         portscan.Config
	lists       config.PortScanLists
	source      string
	modulesPath string
}

// startPortScanDetection brings up inbound port scan detection. It never aborts
// the daemon: a machine that cannot run detection must still get its outbound
// filtering. Every failure is reported, and loudly, so "detection is enabled"
// cannot quietly mean "detection is not running".
func startPortScanDetection(cfg *config.Config, client portScanUI) {
	portScanLifecycleMu.Lock()
	defer portScanLifecycleMu.Unlock()
	startPortScanDetectionMode(cfg, client, false)
}

// startPortScanDetectionMode is startPortScanDetection with the one thing a
// restart does differently: it does not re-arm the startup grace. The grace
// covers connections opened before anything was watching, which holds once, at
// a cold start; after a reload it would only be a blind window, and repeated
// reloads an off switch.
func startPortScanDetectionMode(cfg *config.Config, client portScanUI, restart bool) {
	scanCfg, lists, source, err := cfg.PortScanConfig()
	if err != nil {
		msg := fmt.Sprintf("port scan detection not started, the configuration is invalid: %v", err)
		log.Error("%s", msg)
		client.SendWarningAlert(msg)
		return
	}
	if !scanCfg.Enabled {
		log.Info("[port scan] detection disabled by configuration")
		removeLeftoverBlocks(client)
		return
	}
	if scanCfg.Block.Policy == portscan.BlockNever {
		removeLeftoverBlocks(client)
	}

	// Settings that are valid but that switch detection off, or remove a
	// protection, are said out loud before anything starts. Validate draws its
	// lines where the arithmetic overflows, and accepts values well short of
	// that which leave detection blind.
	for _, w := range scanCfg.Warnings() {
		log.Warning("[port scan] %s", w)
		client.SendWarningAlert(w)
	}

	portScanMu.Lock()
	defer portScanMu.Unlock()
	if portScanMonitor != nil {
		return
	}

	// Kept as requested, before the restart override below, so that a later
	// reload compares like with like. It is not published until Setup has
	// succeeded -- see below.
	requested := portScanRequest{cfg: scanCfg, lists: lists, source: string(source),
		modulesPath: cfg.Ebpf.ModulesPath}
	if restart {
		scanCfg.StartupGrace = 0
	}

	report := func(r portscan.Report) { reportPortScan(client, r) }

	m, chosen, err := portScanSetup(portscan.SetupOptions{
		Config:      scanCfg,
		Source:      source,
		ModulesPath: cfg.Ebpf.ModulesPath,
		NeverCount:  lists.NeverCount,
		NeverBlock:  lists.NeverBlock,
		Report:      report,
		OnError: func(e error) {
			log.Warning("[port scan] %s", e)
			// Degradations also reach the user, not only the log: they mean the feature
			// runs with less protection than configured, and nobody reads the daemon's log
			// on a desktop. Per-packet noise stays in the log.
			if isPortScanDegradation(e) {
				client.SendWarningAlert(fmt.Sprintf("Port scan detection: %v", e))
			}
		},
		// Blocking touches the firewall, so it is only wired up when the
		// policy can actually use it. With policy "never" the nftables table
		// is not even created.
		EnableBlocking: scanCfg.Block.Policy != portscan.BlockNever,
	})
	if err != nil {
		msg := fmt.Sprintf("port scan detection could not start: %v", err)
		log.Error("%s", msg)
		client.SendWarningAlert(msg)
		return
	}

	portScanMonitor = m
	if len(portScanHistory) > 0 {
		m.ReadoptHistory(portScanHistory)
		portScanHistory = nil
	}
	// Published only now that there is a monitor to describe.
	portScanRequested = requested
	client.SetPortScanResponder(portScanUIResponder{m: m})
	portScanClient = client
	m.Start()

	// The effective configuration is logged, not the requested one: Setup may
	// have downgraded the policy when no enforcement backend was available.
	eff := m.Config()
	log.Important("[port scan] detection active (source: %s, block policy: %s, block duration: %s)",
		chosen, eff.Block.Policy, eff.Block.Duration)
	if eff.Block.Policy != scanCfg.Block.Policy {
		// The user asked for blocking and is not getting it: NewMonitor downgrades
		// the policy when no enforcement backend can be built (no nf_tables, no
		// CAP_NET_ADMIN, another instance owning the table), and the log alone would
		// leave the user believing their policy is in force.
		msg := fmt.Sprintf("Port scan detection is running, but blocking was disabled:"+
			" the policy was downgraded from %q to %q because no enforcement backend"+
			" was available.", scanCfg.Block.Policy, eff.Block.Policy)
		log.Warning("[port scan] %s", msg)
		client.SendWarningAlert(msg)
	}
}

// portScanUIResponder is what the user interface holds: the monitor, plus the
// conversion the protocol side needs. It lives here so that daemon/portscan does
// not import a task package for the sake of a struct tag.
type portScanUIResponder struct{ m *portscan.Monitor }

func (r portScanUIResponder) ConfirmBlock(addr netip.Addr, force bool) error {
	return r.m.ConfirmBlockForce(addr, force)
}
func (r portScanUIResponder) ReleaseBlock(addr netip.Addr) (bool, error) { return r.m.Release(addr) }
func (r portScanUIResponder) DismissProposal(addr netip.Addr)            { r.m.DismissProposal(addr) }
func (r portScanUIResponder) Forget(addr netip.Addr) (bool, bool, error) { return r.m.Forget(addr) }

// BlockedList converts at most limit blocks for the user interface, and
// returns the total. Remaining is computed against the daemon's clock and sent
// with the absolute expiry: the user interface may be on another host, whose
// clock may be off.
func (r portScanUIResponder) BlockedList(limit int) ([]portscanblocks.Blocked, int) {
	held, total := r.m.BlockedFirst(limit)
	now := time.Now()
	out := make([]portscanblocks.Blocked, 0, len(held))
	for _, b := range held {
		out = append(out, blockedForUI(b, now))
	}
	return out, total
}

func blockedForUI(b portscan.BlockedSource, now time.Time) portscanblocks.Blocked {
	remaining := int64(b.ExpiresAt.Sub(now).Seconds())
	if remaining < 0 {
		// An entry past its expiry that the expiry pass has not reached yet, or one
		// recorded over the cap: shown as zero, not as a negative countdown.
		remaining = 0
	}
	out := portscanblocks.Blocked{
		Addr:      b.Addr.String(),
		Reason:    b.Reason,
		ExpiresAt: b.ExpiresAt.Unix(),
		Remaining: remaining,
		Stuck:     b.ReleaseFailed,
	}
	if !b.BlockedAt.IsZero() {
		out.BlockedAt = b.BlockedAt.Unix()
	}
	return out
}

// DetectionList converts the history for the user interface: the sources not
// blocked right now, most recently reported first.
func (r portScanUIResponder) DetectionList(limit int) ([]portscanblocks.Detected, int, bool) {
	out, total := detectionsForUI(r.m.History(), r.m.IsBlocked, r.m.IsExempt, r.m.EligibleNow, limit)
	return out, total, r.m.CanBlock()
}

// detectionsForUI keeps the sources not blocked right now -- a blocked one is
// listed as a block, with its countdown -- and converts at most limit of them.
func detectionsForUI(all []portscan.Detection, blocked, exempt func(netip.Addr) bool,
	eligible func(*portscan.ScanEvent) bool, limit int) ([]portscanblocks.Detected, int) {
	out := make([]portscanblocks.Detected, 0, len(all))
	for _, d := range all {
		if blocked(d.Addr) {
			continue
		}
		out = append(out, detectedForUI(d, false, exempt(d.Addr), eligible(d.Scan)))
	}
	total := len(out)
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, total
}

func detectedForUI(d portscan.Detection, blockedNow, exempt, eligible bool) portscanblocks.Detected {
	status := d.Status.String()
	if d.Status == portscan.StatusBlocked && !blockedNow {
		// Blocked once, and the block has ended: it expired, the cap on
		// simultaneous blocks evicted it, or a reload did not carry it over.
		// The daemon does not record which, so the status does not say.
		status = "ended"
	}
	return portscanblocks.Detected{
		Addr:          d.Addr.String(),
		Method:        d.Scan.Method.String(),
		MethodDetail:  d.Scan.MethodDetail,
		Status:        status,
		Reason:        d.Reason,
		FirstReported: d.FirstReported.Unix(),
		LastReported:  d.LastReported.Unix(),
		Eligible:      eligible,
		Exempt:        exempt,
	}
}

// BlockInfo answers PORTSCAN_BLOCK_INFO. The scan goes through ToProtocol, the
// conversion the alert uses, so the details and the alert cannot disagree.
func (r portScanUIResponder) BlockInfo(addr netip.Addr) (portscanblocks.Info, bool) {
	b, rule, ruleErr, ok := r.m.BlockInfo(addr)
	if !ok {
		// Not blocked: a row of the history, then, whose details are the
		// scan and what became of it. There is no firewall rule to show.
		d, found := r.m.Detection(addr)
		if !found {
			return portscanblocks.Info{}, false
		}
		det := detectedForUI(d, false, r.m.IsExempt(addr), r.m.EligibleNow(d.Scan))
		return portscanblocks.Info{
			Blocked:       portscanblocks.Blocked{Addr: det.Addr},
			Scan:          scanForUI(portscan.ToProtocol(d.Scan, portscan.InterfaceName(d.Scan.IfaceIndex), 0)),
			FirewallError: "not blocked: there is no firewall rule for this address",
			Detection:     &det,
		}, true
	}
	info := portscanblocks.Info{Blocked: blockedForUI(b, time.Now()), Firewall: rule}
	if ruleErr != nil {
		info.FirewallError = ruleErr.Error()
	}
	if b.Scan != nil {
		info.Scan = scanForUI(portscan.ToProtocol(b.Scan, portscan.InterfaceName(b.Scan.IfaceIndex), 0))
	}
	return info, true
}

// scanForUI copies the fields of a PortScan message that describe the scan.
func scanForUI(p *protocol.PortScan) *portscanblocks.Scan {
	return &portscanblocks.Scan{
		Method:            p.Method,
		MethodDetail:      p.MethodDetail,
		SrcMAC:            p.SrcMac,
		SrcMACIsSourceOwn: p.SrcMacIsSourceOwn,
		FlagsSummary:      p.FlagsSummary,
		DistinctPorts:     p.DistinctPorts,
		MinPort:           p.MinPort,
		MaxPort:           p.MaxPort,
		SamplePorts:       p.SamplePorts,
		Protocols:         p.Protocols,
		IsProtocolScan:    p.IsProtocolScan,
		Score:             p.Score,
		Interface:         p.Interface,
		Targets:           p.Targets,
		FirstSeenUnixnano: p.FirstSeenUnixnano,
		LastSeenUnixnano:  p.LastSeenUnixnano,
		Anomalies:         p.Anomalies,
		HasTCPEvidence:    p.HasTcpEvidence,
	}
}

// stopPortScanDetection shuts detection down and releases every block it
// installed, so nothing it created outlives the daemon.
func stopPortScanDetection() {
	portScanLifecycleMu.Lock()
	defer portScanLifecycleMu.Unlock()
	stopPortScanDetectionHolding()
}

// stopPortScanDetectionHolding is stopPortScanDetection without the lifecycle
// lock, for reload, which holds it. It returns the blocks that were in force,
// read once the detections still queued have been handled.
func stopPortScanDetectionHolding() []portscan.BlockedSource {
	portScanMu.Lock()
	defer portScanMu.Unlock()
	if portScanMonitor == nil {
		return nil
	}
	log.Info("[port scan] stopping detection and releasing blocks")
	// Unregister before stopping, so a PORTSCAN_BLOCK arriving afterwards does not
	// reach a monitor whose expiry loop is gone. Monitor and BlockManager refuse
	// work after Stop too; this is the outer half of the guard.
	if portScanClient != nil {
		portScanClient.SetPortScanResponder(nil)
		portScanClient = nil
	}
	handOver := portScanMonitor.StopAndHandOver()
	portScanHistory = handOver.History
	portScanMonitor = nil
	// Cleared with the monitor it describes: a stale requested configuration
	// left behind would be compared against on a restart that is a cold start.
	portScanRequested = portScanRequest{}
	return handOver.Blocks
}

// reportPortScan turns a detection into a log line and a UI alert.
func reportPortScan(client portScanUI, r portscan.Report) {
	ev := r.Event
	iface := portscan.InterfaceName(ev.IfaceIndex)

	switch r.Outcome {
	case portscan.OutcomeApplied:
		log.Important("[port scan] %s from %s on %s: blocked for %s",
			ev.Method, ev.Src, iface, r.BlockDuration)
	case portscan.OutcomeRefused:
		log.Warning("[port scan] %s from %s on %s: not blocked (%s)",
			ev.Method, ev.Src, iface, r.Reason)
	default:
		log.Important("[port scan] %s from %s on %s: %d ports, score %d",
			ev.Method, ev.Src, iface, ev.DistinctPorts, ev.Score)
	}
	// The full alert body is not logged: the user interface receives it, the line
	// above names everything needed to find the event, and at a raised
	// AlertsPerMinute the bodies would fill /var.

	msg := portscan.ToProtocol(ev, iface, r.BlockDuration)
	if msg == nil {
		return
	}
	// Only a proposal needs an answer. Marking every scan as needing one would
	// train the user to dismiss them, which is how a real scan gets missed.
	client.SendPortScanAlert(msg, r.Outcome == portscan.OutcomeProposed)
}

// reloadPortScanDetection applies a configuration change to a running daemon,
// through the configuration reload OpenSnitch runs on every write of its file.
// Detection is rebuilt rather than patched: most settings reach the kernel
// (LPM trie, port map, TCX attachments) or are read on the packet path without
// a lock, and a rebuild cannot leave half the new configuration in force.
func reloadPortScanDetection(cfg *config.Config, client portScanUI) {
	scanCfg, lists, source, err := cfg.PortScanConfig()
	if err != nil {
		msg := fmt.Sprintf("port scan configuration not applied, it is invalid: %v", err)
		log.Error("%s", msg)
		client.SendWarningAlert(msg)
		return
	}

	portScanLifecycleMu.Lock()
	defer portScanLifecycleMu.Unlock()

	portScanMu.Lock()
	running := portScanMonitor != nil
	var current portScanRequest
	if running {
		current = portScanRequested
	}
	portScanMu.Unlock()

	if !scanCfg.Enabled {
		if running {
			log.Info("[port scan] disabled by configuration, stopping")
			stopPortScanDetectionHolding()
		}
		return
	}
	if !running {
		log.Info("[port scan] enabled by configuration, starting")
		startPortScanDetectionMode(cfg, client, false)
		return
	}
	if portScanConfigEqual(current, portScanRequest{cfg: scanCfg, lists: lists,
		source: string(source), modulesPath: cfg.Ebpf.ModulesPath}) {
		return
	}
	log.Info("[port scan] configuration changed, restarting detection")

	// Blocks in force are carried across the restart, with the time they had left:
	// the teardown releases every block, and an unrelated edit must not unblock
	// every scanner. They are read by the stop, after it has handled the
	// detections still queued, which under the policy auto may block.
	// The detection history goes across too, through portScanHistory.
	held := stopPortScanDetectionHolding()
	startPortScanDetectionMode(cfg, client, true)

	portScanMu.Lock()
	m := portScanMonitor
	portScanMu.Unlock()
	if m != nil && len(held) > 0 {
		// After the new monitor is up, so the blocks land in a manager that owns
		// them and will expire them. Readopt re-checks the exemption list: a
		// reload is exactly when an operator adds the address that cut them off
		// their own network.
		m.Readopt(held)
	}
	if m != nil {
		m.ReconcileHistory()
	}
}

// portScanConfigEqual reports whether two requests would produce the same
// detector, so an unrelated edit does not rebuild it. Both sides must be
// requests as received, not effective configurations; see portScanRequested.
func portScanConfigEqual(a, b portScanRequest) bool {
	return reflect.DeepEqual(a, b)
}

// isPortScanDegradation reports whether an error means the feature runs with
// less protection than configured, rather than a transient failure worth a log
// line. The detection package marks such errors explicitly, rather than
// leaving this to match message text that drifts.
func isPortScanDegradation(e error) bool {
	return portscan.IsDegradation(e)
}
