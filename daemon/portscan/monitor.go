//go:build linux

package portscan

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BlockOutcome says what the monitor did, or wants to do, about a scan.
type BlockOutcome string

// Block outcomes, as reported to the user.
const (
	// OutcomeNone means no block was applied and none is proposed.
	OutcomeNone BlockOutcome = "none"
	// OutcomeProposed means the user is being asked whether to block.
	OutcomeProposed BlockOutcome = "proposed"
	// OutcomeApplied means a block was installed without asking.
	OutcomeApplied BlockOutcome = "applied"
	// OutcomeRefused means no block was applied: the detection is not enough
	// on its own (nothing arrived that only a scanner sends), the source is on
	// the never-block list, or the firewall refused the block.
	OutcomeRefused BlockOutcome = "refused"
)

// Report is what the daemon hands to the user interface.
type Report struct {
	Event   *ScanEvent
	Outcome BlockOutcome
	// Reason explains OutcomeRefused, and is empty otherwise.
	Reason string
	// BlockDuration is how long a block would last, or does last.
	BlockDuration time.Duration
}

// ReportFunc receives every scan the monitor decides to surface.
type ReportFunc func(Report)

// PacketSource is anything that produces Probes.
type PacketSource interface {
	// Run blocks, feeding probes to the callback given at construction. It must
	// tolerate being called after Close has returned, and return promptly: Close is
	// the only thing that can wake a blocked Run, so Stop has to be able to call it
	// before Run is entered (TestPacketSourceRunAfterCloseIsSafe).
	Run()
	// Close stops it. It must be safe to call concurrently with Run, and safe
	// to call more than once.
	Close() error
	// StartedAt is the wall-clock time the source began, used only to give
	// events a human-readable timestamp.
	StartedAt() time.Time
	// NowNs reads the clock the source stamps Probe.TimeNs from. The two sources
	// do not share one -- eBPF stamps nanoseconds since boot, AF_PACKET time since
	// the source was built -- and the startup grace, Expire and alert timestamps all
	// need "now" in the probes' own clock.
	NowNs() uint64
}

// Monitor wires the engine, the packet source, the host view and the blocker
// together, and is what the daemon starts and stops.
type Monitor struct {
	mu  sync.Mutex
	cfg Config

	engine  *Engine
	host    *SystemHostInfo
	source  PacketSource
	blocks  *BlockManager
	report  ReportFunc
	onError func(error)

	// pending holds sources the user has been asked about but has not
	// answered yet, so a late answer can still be honoured and a repeated
	// detection does not ask twice.
	pending map[netip.Addr]proposal
	// history keeps every reported source for HistoryRetention, so that the
	// user can see it, and block it, once its alert is gone.
	history *History
	// blockOpMu makes a block or a release, and the status the history
	// records for it, one step: two concurrent requests on one address would
	// otherwise leave the history saying the opposite of the firewall. It is
	// taken before m.mu and the history's lock, never after.
	blockOpMu sync.Mutex
	// droppedSaid is History.Dropped when checkHistoryFull last warned, so
	// that a warning counts everything since the previous one, not the last
	// minute only. Only the maintenance goroutine touches it.
	droppedSaid uint64
	// afterApply, when set by a test, runs between installing a block and
	// recording its status, to hold that window open.
	afterApply func()
	// lastSourceStats is the previous reading of the packet source's own
	// counters, so maintenance can report a rise rather than a total.
	lastSourceStats map[string]uint64
	// said is when each kind of maintenance warning was last given, and how
	// large the condition was then; see sayLocked.
	said map[string]saidMark
	// now is the clock checkSourceDegradation paces its warnings by; nil
	// means time.Now.
	now func() time.Time

	// events carries a crossing off the packet path. See onProbe.
	events chan *ScanEvent
	// eventsDone closes when the event goroutine has drained and exited.
	eventsDone chan struct{}
	// startDone closes once Start has finished wiring everything up, so a Stop
	// concurrent with Start does not close the source before Run is entered on it.
	startDone chan struct{}
	// eventsDropped counts crossings discarded because the channel was full.
	// Atomic: written from the packet path, read by maintenance.
	eventsDropped atomic.Uint64

	running bool
	// stopped stays true once Stop has run. It is distinct from !running: a
	// monitor that was never started still holds a usable block manager, but
	// one that has been stopped has released everything and has no expiry loop
	// left, so a block installed after that is one nobody owns.
	stopped bool
	stop    chan struct{}
	done    chan struct{}
}

// eventQueueDepth is how many crossings may wait for the firewall. Crossings are
// capped by AlertsPerMinute, so this absorbs a burst; a deeper queue would only
// delay the moment the drop counter says the firewall is not keeping up.
const eventQueueDepth = 64

// MonitorOptions collects everything Monitor needs from the daemon.
type MonitorOptions struct {
	Config Config
	// NeverCount suppresses detection for these prefixes entirely, down to the
	// kernel filter. It is separate from NeverBlock: writing a prefix off as not
	// worth watching is a bigger decision than "never cut me off from this", and
	// an operator who means the second must not get the first -- least of all for
	// their own LAN, where an internal attacker scans from.
	NeverCount []netip.Prefix
	// NeverBlock forbids installing a firewall rule against these prefixes,
	// while leaving detection fully active for them.
	NeverBlock []netip.Prefix
	// Report is called for every surfaced scan. Required.
	Report ReportFunc
	// NewBlocker builds the enforcement backend. If nil, blocking is disabled
	// and Block.Policy is forced to BlockNever, so the user is never asked a
	// question the daemon could not act on.
	NewBlocker func(time.Duration) (Blocker, error)
	// NewSource builds the packet source. Required. It receives the host view,
	// already populated, because the eBPF program keeps only packets aimed at the
	// host's own addresses and would see nothing with an empty map.
	NewSource func(host *SystemHostInfo, onProbe func(*Probe), onError func(error)) (PacketSource, error)
	// OnError receives non-fatal runtime errors.
	OnError func(error)
}

// NewMonitor validates the options and builds a stopped monitor.
func NewMonitor(opts MonitorOptions) (*Monitor, error) {
	if opts.Report == nil {
		return nil, fmt.Errorf("portscan: a Report callback is required")
	}
	if opts.NewSource == nil {
		return nil, fmt.Errorf("portscan: a packet source constructor is required")
	}
	cfg := opts.Config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opts.OnError == nil {
		opts.OnError = func(error) {}
	}

	host, err := NewSystemHostInfo(opts.NeverCount, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("portscan: reading the host network state: %w", err)
	}

	host.SetNeverBlock(opts.NeverBlock)
	host.SetOnError(opts.OnError)
	if err := host.InfraError(); err != nil {
		// The never-block list may be incomplete: the addresses this host needs for a
		// network at all come from files that could not be read in full. Detection
		// still runs -- refusing to start would give whoever broke those files an off
		// switch -- but the gap is said out loud.
		opts.OnError(degraded("the never-block list may be incomplete: %w", err))
	}

	m := &Monitor{
		cfg:        cfg,
		host:       host,
		report:     opts.Report,
		onError:    opts.OnError,
		pending:    map[netip.Addr]proposal{},
		history:    NewHistory(),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		events:     make(chan *ScanEvent, eventQueueDepth),
		eventsDone: make(chan struct{}),
		startDone:  make(chan struct{}),
	}

	// Everything built below is released if this function does not return a
	// working monitor: NewNftBlocker installs its table and rules on construction,
	// and a later failure (no eBPF module, an interface that cannot be bound) must
	// not leave them behind with nothing to remove them.
	started := false
	defer func() {
		if started {
			return
		}
		if m.blocks != nil {
			m.blocks.Stop()
		}
		if m.source != nil {
			_ = m.source.Close()
		}
		host.Stop()
	}()

	if cfg.Block.Policy != BlockNever {
		if opts.NewBlocker == nil {
			// Asking the user to authorise something the daemon cannot carry
			// out would be worse than not asking: the user would believe they
			// were protected. Degrade loudly instead.
			m.cfg.Block.Policy = BlockNever
			opts.OnError(degraded("no enforcement backend available, blocking disabled and detection left in alert-only mode"))
		} else {
			b, err := opts.NewBlocker(cfg.Block.Duration)
			if err != nil {
				m.cfg.Block.Policy = BlockNever
				opts.OnError(degraded("enforcement backend unavailable (%w), blocking disabled and detection left in alert-only mode", err))
			} else {
				bm, err := NewBlockManager(b, cfg.Block, host.IsNeverBlock)
				if err != nil {
					return nil, err
				}
				// A daemon that cannot say it failed to undo what it did to the firewall
				// gives nobody a way to find out.
				bm.SetOnError(opts.OnError)
				m.blocks = bm
			}
		}
	}

	// The engine's clock origin is the packet source's, so both agree on what
	// Probe.TimeNs means. The source is built first for that reason.
	src, err := opts.NewSource(host, m.onProbe, opts.OnError)
	if err != nil {
		return nil, err
	}
	m.source = src

	// The engine is built in the source's clock, read from the source itself:
	// zero would be right for AF_PACKET only, and on the eBPF path would
	// disable the startup grace and state expiry.
	nowNs := src.NowNs()
	eng, err := NewEngine(m.cfg, host, nowNs)
	if err != nil {
		return nil, err
	}
	eng.SetWallClockAnchor(time.Now(), nowNs)
	m.engine = eng
	m.applyInterfaceRestriction()

	started = true
	return m, nil
}

// Start begins detection.
func (m *Monitor) Start() {
	m.mu.Lock()
	// Stopped is final: a second Start would close m.done again and panic in a
	// goroutine no caller can recover.
	if m.running || m.stopped {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	// Closed once everything below is wired, so Stop cannot close the source
	// before Run has been started on it.
	defer close(m.startDone)

	m.host.Start()
	if m.blocks != nil {
		m.blocks.Start(30 * time.Second)
	}
	go m.eventLoop()
	go func() {
		defer close(m.done)
		// A Stop that has already run means there is nothing to read and the
		// source is closed or closing. Entering Run is permitted (see
		// PacketSource) but pointless, and skipping it keeps the common case of
		// a cancelled start from touching the source at all.
		select {
		case <-m.stop:
			return
		default:
		}
		m.source.Run()
	}()
	go m.maintenance()
}

// Stop ends detection and releases every block it installed.
func (m *Monitor) Stop() {
	m.stopHolding()
}

// stopHolding is Stop, returning the blocks in force once the events still
// queued have been handled and before the block manager releases them: under
// the policy auto, handling them can install blocks a capture taken before
// Stop would miss. Nil if the monitor was already stopped.
func (m *Monitor) stopHolding() []BlockedSource {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return nil
	}
	wasRunning := m.running
	m.running = false
	m.stopped = true
	close(m.stop)
	m.mu.Unlock()

	// Wait for Start to finish wiring before touching anything it owns. It
	// cannot hang: wasRunning means Start took the one path that closes startDone.
	if wasRunning {
		<-m.startDone
	}

	// The cleanup runs whether or not Start ever did: a monitor built and then
	// stopped holds what NewMonitor installed (the TCX program on every
	// interface, the ring buffer reader or the AF_PACKET sockets, the nftables
	// table), and returning early on !running would leave it with no owner.
	_ = m.source.Close()
	if wasRunning {
		// Only wait for goroutines that were started. The event goroutine is
		// waited on here, before the block manager is stopped below, so a
		// crossing already accepted still reaches a live firewall instead of a
		// stopped one.
		<-m.done
		<-m.eventsDone
	}
	m.host.Stop()
	held := m.Blocked()
	if m.blocks != nil {
		m.blocks.Stop()
	}
	return held
}

// AddressSink is implemented by a packet source that holds its own copy of the
// host's addresses, as the eBPF program does. A DHCP renewal, a new interface or
// a rotating IPv6 privacy address changes the set, and a stale copy silently
// stops counting packets aimed at the new address.
type AddressSink interface {
	SyncLocalAddrs(addrs []netip.Addr) error
}

// drainPendingReports surfaces crossings the alert limiter refused earlier;
// see Engine.DrainPending. It runs once a minute, the limiter's own window.
func (m *Monitor) drainPendingReports(nowNs uint64) {
	for _, ev := range m.engine.DrainPending(nowNs) {
		select {
		case m.events <- ev:
		default:
			m.eventsDropped.Add(1)
		}
	}
}

// checkDroppedEvents reports crossings the firewall could not keep up with.
// Dropping them beats stalling the ring buffer reader, but under "auto" the user
// would otherwise believe every detected scanner was blocked.
func (m *Monitor) checkDroppedEvents() {
	n := m.eventsDropped.Swap(0)
	if n == 0 || !m.say("dropped-events", uint64(n)) {
		return
	}
	m.onError(degraded("%d detected scan(s) were not acted on in the last"+
		" minute because the enforcement backend could not keep up; detection is"+
		" running but blocking is falling behind"+pacedNote, n))
}

// checkHostView reports that this host has no addresses of its own, a state in
// which nothing can be detected: Engine.accept counts only packets aimed at one
// of them, and the daemon would look like a machine on a quiet network. Not
// fatal -- a daemon started before the network is up has none yet -- but made
// visible if it persists.
func (m *Monitor) checkHostView() {
	if m.host.LocalAddrCount() > 0 || !m.say("no-address", 1) {
		return
	}
	m.onError(degraded("this host has no local addresses, so no inbound" +
		" packet can be counted and detection cannot report anything; it is running" +
		" but blind until an address appears" + pacedNote))
}

// maintenance runs the periodic housekeeping that must never be on the packet
// path: expiring idle source state and stale unanswered prompts, and keeping a
// kernel-side copy of the host's addresses current.
func (m *Monitor) maintenance() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			now := m.source.NowNs()
			m.engine.Expire(now)
			m.expirePending()
			m.engine.RefreshWallClockAnchor(time.Now(), now)
			m.syncSourceAddrs()
			m.refreshSourceInterfaces()
			m.checkSourceDegradation()
			m.checkEvictionPressure()
			m.checkHistoryFull()
			m.checkDroppedEvents()
			m.checkHostView()
			m.drainPendingReports(now)
		}
	}
}

// InterfaceWatcher is implemented by a packet source that can start watching
// interfaces which appear after it was built. Both of them can.
type InterfaceWatcher interface {
	// RefreshInterfaces begins watching any interface that has appeared or come
	// up since the last call, and reports which ones it started on.
	RefreshInterfaces() ([]string, error)
}

// refreshSourceInterfaces keeps coverage matching the machine's interfaces. A
// VPN tunnel connects after login, a container bridge is created on demand, a
// laptop boots before it associates; each would otherwise stay unwatched while
// detection reports itself running. A minute's granularity rather than a
// netlink subscription: the window is bounded and visible, and it avoids a
// second long-lived socket and failure mode.
func (m *Monitor) refreshSourceInterfaces() {
	w, ok := m.source.(InterfaceWatcher)
	if !ok {
		return
	}
	added, err := w.RefreshInterfaces()
	if err != nil {
		m.onError(fmt.Errorf("portscan: watching newly available interfaces: %w", err))
	}
	if len(added) > 0 {
		// Said out loud rather than done quietly: an interface appearing is a
		// change in what the daemon covers, and the user was previously never
		// told that their coverage had a hole in it.
		m.onError(fmt.Errorf("portscan: now also watching %s", strings.Join(added, ", ")))
		m.applyInterfaceRestriction()
	}
}

// applyInterfaceRestriction pushes the operator's interface list to the engine,
// as indices, so the restriction does not rest on the sources alone. Only when
// the operator named interfaces: with the default empty list, a filter built
// from whatever is attached now could only drop probes from an interface just
// added.
func (m *Monitor) applyInterfaceRestriction() {
	if len(m.cfg.Interfaces) == 0 {
		return
	}
	allowed := map[uint32]bool{}
	for _, name := range m.cfg.Interfaces {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			// Not fatal: a configured interface may legitimately not exist yet,
			// which is the case this whole refresh is here for.
			continue
		}
		allowed[uint32(ifi.Index)] = true
	}
	if len(allowed) == 0 {
		// Storing an empty map would mean "allow everything", which is the
		// opposite of what the operator asked for. Leave the previous list in
		// place instead.
		return
	}
	m.engine.SetAllowedInterfaces(allowed)
}

// evictionPressureTurnovers is how many complete turnovers of the source table
// in one minute count as an alarm. An ordinary desktop sees a handful of new
// remote addresses a minute against a table sized for thousands; two turnovers
// a minute means something presents several times MaxSources addresses.
const evictionPressureTurnovers = 2

// checkEvictionPressure reports a flood of distinct source addresses: the one
// detection bypass a bounded table cannot close (see sourceTable.evictOne). The alert
// does not claim a scan is in progress, because the engine does not know; it
// knows its memory is being churned faster than legitimate traffic churns it.
func (m *Monitor) checkEvictionPressure() {
	evicted, turnovers := m.engine.EvictionPressure()
	if turnovers < evictionPressureTurnovers || !m.say("eviction", evicted) {
		return
	}
	// The advice says what raising MaxSources buys and what it costs: an attacker
	// refills a larger table for the same effort.
	m.mu.Lock()
	maxSources := m.cfg.MaxSources
	m.mu.Unlock()
	m.onError(degraded("%d source addresses displaced in the last minute,"+
		" %.1f times the whole table: something is presenting far more distinct source"+
		" addresses than ordinary traffic does, which is how a scan is hidden from a"+
		" detector with bounded memory. PortScan.MaxSources is %d, or about %s of"+
		" tracked state once full; raising it makes the table harder to cycle through"+
		" but costs that memory and does not stop an attacker refilling the larger"+
		" table for the same effort"+pacedNote,
		evicted, turnovers, maxSources, approxTableBytes(maxSources)))
}

// checkHistoryFull says when detections were not recorded because the
// history is full of detections with TCP evidence, which a newer detection
// never displaces (see History.makeRoomLocked).
func (m *Monitor) checkHistoryFull() {
	total := m.history.Dropped()
	dropped := total - m.droppedSaid
	if dropped == 0 || !m.say("history-full", dropped) {
		return
	}
	m.droppedSaid = total
	m.onError(degraded("%d port scan detections were not kept in the detection history"+
		" since this was last said: it holds %d sources reported in the last %d days, and"+
		" none it holds may be replaced by a newer detection, since they have TCP evidence"+
		" or were blocked or released by the user (only a detection without TCP evidence that"+
		" the user has not acted on is replaced). This keeps a flood of forged detections from erasing a"+
		" real scan from the list; the detections not kept were still reported as alerts,"+
		" but cannot be blocked from the list once their alert is gone. So many sources is"+
		" what a scan with forged or decoy source addresses produces"+pacedNote,
		dropped, MaxHistory, int(HistoryRetention.Hours()/24)))
}

// pacedNote ends every warning sayLocked paces, so that its silence
// afterwards is not read as the condition having ended.
const pacedNote = "; this warning is given at most once an hour, and again sooner if it grows tenfold"

// saidMark is when a maintenance warning was last given, and the size of
// what it said.
type saidMark struct {
	at   time.Time
	size uint64
}

// sayLocked reports whether a maintenance warning of this kind should be
// given now, of a condition of this size, and records it if so. m.mu must be
// held.
//
// Maintenance runs every minute, and a condition that lasts was said every
// minute: ordinary traffic can keep a budget spent for hours -- a machine
// seeding to twenty peers does -- and anyone can keep a flood of forged
// addresses going, and one warning a minute for one condition teaches the
// user to ignore them all. Each kind is said at most once an hour, unless it
// has grown tenfold since it was last said: a warning that read "+300" must
// not stand for a flood refusing a thousand times more.
func (m *Monitor) sayLocked(kind string, size uint64, now time.Time) bool {
	if m.said == nil {
		m.said = map[string]saidMark{}
	}
	if last, ok := m.said[kind]; ok && now.Sub(last.at) < time.Hour &&
		size < 10*max(last.size, 1) {
		return false
	}
	m.said[kind] = saidMark{at: now, size: size}
	return true
}

// say is sayLocked at the monitor's clock, taking the lock.
func (m *Monitor) say(kind string, size uint64) bool {
	now := time.Now()
	if m.now != nil {
		now = m.now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sayLocked(kind, size, now)
}

// approxTableBytes renders the memory a full source table holds, for the
// message above. Approximate on purpose: the point is the order of magnitude,
// which is what an operator needs in order to decide.
func approxTableBytes(maxSources int) string {
	const perSource = 288 // one tableEntry plus its map slot, measured
	b := int64(maxSources) * perSource
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%d MB", b>>20)
	case b >= 1<<10:
		return fmt.Sprintf("%d KB", b>>10)
	default:
		return fmt.Sprintf("%d bytes", b)
	}
}

// SourceStats is implemented by a packet source that can report how much it
// dropped. Both sources do; it is optional for a source that cannot.
type SourceStats interface {
	Stats() (map[string]uint64, error)
}

// checkSourceDegradation reads, once a minute, whether the kernel half is
// dropping probes, so a degraded detector can be told from a quiet network.
// Each counter's losses, and a failure to read them, are said as sayLocked
// allows:
//
//   - ringbuf_full (eBPF) and kernel_dropped (AF_PACKET): probes thrown away
//     because userspace was not draining fast enough;
//   - rate_limited: probes refused by the kernel's aggregate budget, which a
//     flood above it takes from every source, a real scan's included.
//
// source_rate_limited, a source refused by its own budget, is not reported:
// one peer's download goes past it, and it costs no other source anything.
func (m *Monitor) checkSourceDegradation() {
	src, ok := m.source.(SourceStats)
	if !ok {
		return
	}
	// A failed read may still return the counters that could be read, and
	// those are checked: skipping the whole check on any error hid the
	// aggregate budget's losses behind one unreadable socket.
	stats, err := src.Stats()
	now := time.Now()
	if m.now != nil {
		now = m.now()
	}
	m.mu.Lock()
	var report []error
	if err != nil && m.sayLocked("stats", 1, now) {
		report = append(report, degraded("reading the packet source's loss counters: %w"+pacedNote, err))
	}
	// The reference keeps the last value read of every counter: a reading
	// that missed one, or returned nothing, must not make the next reading's
	// whole total look like a minute's loss, nor lose the minute after it.
	prev := m.lastSourceStats
	if stats != nil {
		merged := make(map[string]uint64, len(prev)+len(stats))
		for k, v := range prev {
			merged[k] = v
		}
		for k, v := range stats {
			merged[k] = v
		}
		m.lastSourceStats = merged
	}
	if prev == nil || stats == nil {
		m.mu.Unlock()
		for _, err := range report {
			m.onError(err)
		}
		return
	}
	for _, c := range []struct {
		key, what string
	}{
		{"ringbuf_full", "the ring buffer was full: probes were dropped before reaching the daemon"},
		{"kernel_dropped", "the packet socket's receive buffer was full: probes were dropped before reaching the daemon"},
		{"rate_limited", "the kernel budget refused probes: detection is degraded for every source, not only the one flooding"},
	} {
		cur, read := stats[c.key]
		old, had := prev[c.key]
		if !read || !had {
			continue
		}
		d := cur - old
		if d == 0 || cur < old || !m.sayLocked(c.key, d, now) {
			continue
		}
		report = append(report, degraded("detection degraded in the last minute: %s (%s +%d)"+pacedNote,
			c.what, c.key, d))
	}
	m.mu.Unlock()
	for _, err := range report {
		m.onError(err)
	}
}

// syncSourceAddrs pushes the current address list to a source that keeps one.
func (m *Monitor) syncSourceAddrs() {
	sink, ok := m.source.(AddressSink)
	if !ok {
		return
	}
	if err := sink.SyncLocalAddrs(m.host.LocalAddrs()); err != nil {
		m.onError(degraded("refreshing the kernel-side address list: %w", err))
	}
}

// pendingTTL is how long an unanswered "block this source?" prompt stays
// actionable. Beyond it the question is stale: the scan is long over, and
// applying a block then would surprise the user.
const pendingTTL = 10 * time.Minute

// proposal is a block the user has been asked about.
type proposal struct {
	// at is when the question was first asked; pendingTTL runs from it.
	at time.Time
	// scan is the latest detection of the source, kept with the block if the
	// user accepts.
	scan *ScanEvent
}

func (m *Monitor) expirePending() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for addr, p := range m.pending {
		if now.Sub(p.at) > pendingTTL {
			delete(m.pending, addr)
			m.history.expireAsked(addr)
		}
	}
}

// onProbe is the packet-path callback. A crossing is handed to another
// goroutine rather than acted on here: this runs on the goroutine that drains
// the kernel's ring buffer, and handling an event takes the block manager's lock
// and a netlink round trip -- about a thousand times an ordinary probe's cost,
// time during which the kernel drops what it cannot fit, at the moment someone
// is scanning. The queue is bounded and lossy; a crossing that cannot be queued
// is counted and dropped, since crossings are capped by AlertsPerMinute and a
// full queue means the firewall is not keeping up.
func (m *Monitor) onProbe(p *Probe) {
	ev := m.engine.Process(p)
	if ev == nil {
		return
	}
	select {
	case m.events <- ev:
	default:
		m.eventsDropped.Add(1)
	}
}

// eventLoop applies the block policy and surfaces scans, off the packet path.
func (m *Monitor) eventLoop() {
	defer close(m.eventsDone)
	for {
		select {
		case ev := <-m.events:
			m.handleEvent(ev)
		case <-m.stop:
			// Drain what is already queued before leaving, so a crossing that
			// was accepted is acted on rather than silently discarded at
			// shutdown. The queue is bounded, so this terminates.
			for {
				select {
				case ev := <-m.events:
					m.handleEvent(ev)
				default:
					return
				}
			}
		}
	}
}

// handleEvent applies the block policy and surfaces the scan.
func (m *Monitor) handleEvent(ev *ScanEvent) {
	m.blockOpMu.Lock()
	rep := m.decide(ev)
	m.blockOpMu.Unlock()
	m.report(rep)
}

// decide applies the block policy to a detection and records it in the
// history. blockOpMu is held.
func (m *Monitor) decide(ev *ScanEvent) Report {
	m.mu.Lock()
	policy := m.cfg.Block.Policy
	duration := m.cfg.Block.Duration
	m.mu.Unlock()

	rep := Report{Event: ev, Outcome: OutcomeNone, BlockDuration: duration}

	switch {
	case policy == BlockNever:
		rep.Outcome = OutcomeNone

	case m.blocks != nil && m.blocks.IsBlocked(ev.Src):
		// Before the eligibility test: a source already blocked -- by a forced
		// block, say -- is still blocked when it is detected again without
		// evidence, and is not reported, or recorded, as refused.
		rep.Outcome = OutcomeApplied
		// The packet sources sit before netfilter, so a blocked source is still
		// scored, and this is its latest detection: the block shows it, unless it
		// is weaker than the one the block shows.
		if cur, ok := m.blocks.Lookup(ev.Src); !ok || cur.Scan == nil || ev.HasTCPEvidence || !cur.Scan.HasTCPEvidence {
			m.blocks.UpdateScan(ev.Src, ev)
		}

	case !ev.BlockEligible:
		rep.Outcome = OutcomeRefused
		if !ev.HasTCPEvidence {
			// Without a probe only a scanner sends (a UDP scan, an ACK scan, a
			// protocol scan), the source address costs nothing to forge, so the
			// accusation must not move a firewall. HasTCPEvidence means such a probe
			// contributed, not that TCP arrived: the reason says what it means.
			rep.Reason = "no corroborating evidence: nothing arrived that only a scanner sends," +
				" and the source address of such traffic costs nothing to forge"
		} else {
			rep.Reason = "blocking is not permitted for this source"
		}

	case m.host.IsNeverBlock(ev.Src):
		rep.Outcome = OutcomeRefused
		rep.Reason = "the source is on the never-block list"

	case policy == BlockAuto:
		if err := m.applyBlock(ev.Src, ev.MethodDetail, ev); err != nil {
			rep.Outcome = OutcomeRefused
			rep.Reason = err.Error()
		} else {
			rep.Outcome = OutcomeApplied
		}

	case policy == BlockAsk:
		m.mu.Lock()
		// The question keeps the time it was first asked, so that a source still
		// scanning cannot keep it alive for ever, and the latest detection, which
		// is what the block will be shown with.
		p, already := m.pending[ev.Src]
		if !already {
			p.at = time.Now()
		}
		p.scan = ev
		m.pending[ev.Src] = p
		rep.Outcome = OutcomeProposed
		// Recorded under the same lock as the question: an answer confirmed in
		// between would otherwise be overwritten by "asked", with no question
		// left for the expiry to turn into "unanswered".
		m.history.Record(ev, StatusAsked, "")
		m.mu.Unlock()
		return rep
	}

	m.history.Record(ev, historyStatus(rep.Outcome), rep.Reason)
	return rep
}

// historyStatus is what an outcome makes of a source in the history.
func historyStatus(o BlockOutcome) DetectionStatus {
	switch o {
	case OutcomeApplied:
		return StatusBlocked
	case OutcomeRefused:
		return StatusRefused
	case OutcomeProposed:
		return StatusAsked
	default:
		return StatusDetected
	}
}

func (m *Monitor) applyBlock(addr netip.Addr, reason string, scan *ScanEvent) error {
	if m.blocks == nil {
		return fmt.Errorf("no enforcement backend")
	}
	return m.blocks.BlockScan(addr, reason, scan)
}

// ConfirmBlock is called when the user accepts a proposed block.
//
// It re-checks the exemption list rather than trusting the request. The
// question came from a user interface, over a socket; the daemon must not
// install a firewall rule against its own gateway because a message said so.
func (m *Monitor) ConfirmBlock(addr netip.Addr) error {
	return m.ConfirmBlockForce(addr, false)
}

// ErrNotEligible is returned for a source whose detection is not enough to
// block it -- nothing arrived that only a scanner sends, and its address costs
// nothing to forge -- when the request does not insist.
var ErrNotEligible = errors.New("portscan: the detection is not enough to block this source")

// ConfirmBlockForce is ConfirmBlock for a source the user chose from the
// history, after its question expired or was answered no: a scan is
// reconnaissance, and the attempt it prepares can come days later. force
// blocks a source whose detection is not eligible: the user was warned that
// its address may be forged. The never-block list is never overridden.
func (m *Monitor) ConfirmBlockForce(addr netip.Addr, force bool) error {
	addr = normalizeAddr(addr)
	m.mu.Lock()
	p, wasPending := m.pending[addr]
	delete(m.pending, addr)
	policy := m.cfg.Block.Policy
	stopped := m.stopped
	m.mu.Unlock()

	if policy == BlockNever {
		return fmt.Errorf("portscan: blocking is disabled by configuration")
	}
	if stopped {
		// Detection is stopped: the expiry loop is gone and the release pass has run,
		// so a block installed now would be one nobody owns or removes.
		return fmt.Errorf("portscan: detection is not running")
	}
	// The exemption list is consulted first, so a request for an address the
	// host must never block is refused as exempt rather than as unknown -- the
	// caller needs to know which it is.
	if m.host.IsNeverBlock(addr) {
		return fmt.Errorf("%w: %s", ErrExempt, addr)
	}
	reason := "confirmed by the user"
	if !wasPending {
		// Not a reply to any question we asked. The request is honoured only for a
		// source this daemon actually reported -- still in the engine, or in the
		// history -- under the policy it applied then: the message comes over a
		// socket the daemon does not control, and must not be a way to drop any
		// address. The raw score cannot decide this -- one forged packet makes it
		// non-zero, and a reported protocol scan has none.
		d := m.engine.LookupForBlock(addr)
		h, inHistory := m.history.Lookup(addr)
		if !d.Reported && !inHistory {
			return fmt.Errorf("portscan: %s was never reported as scanning; refusing to block an address no detection reported", addr)
		}
		if m.blocks != nil && m.blocks.IsBlocked(addr) {
			// Already blocked: answered as done, and not extended. Repeating the
			// request must not keep a source blocked for as long as the history
			// remembers it.
			return nil
		}
		// The history's detection is judged by the configuration in force now,
		// as the engine judges its own: one recorded under the policy "never",
		// or before RequireTCPEvidence changed, carries an eligibility that no
		// longer applies.
		eligible := (d.Reported && d.BlockEligible) || (inHistory && m.EligibleNow(h.Scan))
		if !eligible && !force {
			return fmt.Errorf("%w: %s; nothing arrived that only a scanner sends, and its address may be forged", ErrNotEligible, addr)
		}
		reason = "blocked by the user after the detection"
		if !eligible {
			reason = "blocked by the user, on a detection not enough to block on its own"
		}
		if inHistory {
			p.scan = h.Scan
		}
	}
	m.blockOpMu.Lock()
	defer m.blockOpMu.Unlock()
	if err := m.applyBlock(addr, reason, p.scan); err != nil {
		return err
	}
	if m.afterApply != nil {
		m.afterApply()
	}
	m.history.SetStatus(addr, StatusBlocked, "")
	return nil
}

// EligibleNow reports whether a recorded detection is enough to block its
// source under the configuration in force now, as Engine.blockEligible
// judges a live one. The policy "never" is left to CanBlock.
func (m *Monitor) EligibleNow(ev *ScanEvent) bool {
	m.mu.Lock()
	require := m.cfg.Block.RequireTCPEvidence
	m.mu.Unlock()
	return ev != nil && (!require || ev.HasTCPEvidence)
}

// ReleaseBlock removes a block early.
func (m *Monitor) ReleaseBlock(addr netip.Addr) error {
	_, err := m.Release(addr)
	return err
}

// Release is ReleaseBlock, also saying whether there was a block to release,
// so the user interface logs and answers a release only when one happened.
func (m *Monitor) Release(addr netip.Addr) (bool, error) {
	if m.blocks == nil {
		return false, nil
	}
	addr = normalizeAddr(addr)
	m.mu.Lock()
	stopped := m.stopped
	m.mu.Unlock()
	if stopped {
		// Stop already released everything it knew about.
		return false, nil
	}
	// Only a real release forgets the score. Forgetting it for any address would
	// let whoever can reach the socket keep a scanner below the threshold with a
	// release now and then; forgetting it after a genuine release keeps the source
	// from being one probe away from another block.
	if !m.blocks.IsBlocked(addr) {
		// Nothing to release. Not an error: the caller may be answering about a
		// block that has already expired, and idempotence is what the Blocker
		// contract asks for.
		return false, nil
	}
	m.engine.Forget(addr)
	m.blockOpMu.Lock()
	defer m.blockOpMu.Unlock()
	if err := m.blocks.Unblock(addr); err != nil {
		return true, err
	}
	m.history.SetStatus(addr, StatusReleased, "")
	return true, nil
}

// Forget removes a source from the list at the user's request: its block is
// released if it has one, a question still open about it is dropped, and its
// history entry is deleted. It reports whether there was anything to remove.
//
// For a source that is not blocked, the engine's state is kept, as on a
// release of nothing: forgetting it for any listed address would let whoever
// reaches the socket keep a scanner below the threshold with a deletion now
// and then. A source blocked again between the release and the deletion
// keeps its entry, and its block.
//
// released says whether a block was lifted on the way: Release then forgets
// the engine's state, as for any genuine release, and the source that scans
// again is detected afresh.
//
// A stopped monitor refuses: during a reload its blocks have already been
// handed to the next monitor, which would put back the block just "deleted".
func (m *Monitor) Forget(addr netip.Addr) (removed, released bool, err error) {
	addr = normalizeAddr(addr)
	if m.isStopped() {
		return false, false, fmt.Errorf("portscan: detection is not running")
	}
	released, err = m.Release(addr)
	if err != nil {
		// Still in the firewall: the entry stays, so that the list goes on
		// showing what is enforced.
		return released, released, err
	}
	m.blockOpMu.Lock()
	defer m.blockOpMu.Unlock()
	if m.isStopped() {
		return released, released, fmt.Errorf("portscan: detection is not running")
	}
	if m.IsBlocked(addr) {
		return released, released, nil
	}
	m.mu.Lock()
	_, wasPending := m.pending[addr]
	delete(m.pending, addr)
	m.mu.Unlock()
	inHistory := m.history.Remove(addr)
	return released || inHistory || wasPending, released, nil
}

func (m *Monitor) isStopped() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopped
}

// DismissProposal records that the user declined to block a source.
func (m *Monitor) DismissProposal(addr netip.Addr) {
	addr = normalizeAddr(addr)
	// With the decision of a detection, which records "asked" for it.
	m.blockOpMu.Lock()
	defer m.blockOpMu.Unlock()
	m.mu.Lock()
	_, wasPending := m.pending[addr]
	delete(m.pending, addr)
	m.mu.Unlock()
	if wasPending {
		m.history.SetStatus(addr, StatusIgnored, "")
	}
}

// Detections lists at most limit sources of the history, most recently
// reported first, and how many it holds.
func (m *Monitor) Detections(limit int) ([]Detection, int) {
	return m.history.List(limit)
}

// Detection returns the history entry of addr.
func (m *Monitor) Detection(addr netip.Addr) (Detection, bool) {
	return m.history.Lookup(addr)
}

// IsBlocked reports whether addr is blocked right now.
func (m *Monitor) IsBlocked(addr netip.Addr) bool {
	return m.blocks != nil && m.blocks.IsBlocked(addr)
}

// CanBlock reports whether this monitor can install a block at all: it has a
// firewall backend and the policy is not "never".
func (m *Monitor) CanBlock() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blocks != nil && m.cfg.Block.Policy != BlockNever && !m.stopped
}

// IsExempt reports whether addr is on the never-block list.
func (m *Monitor) IsExempt(addr netip.Addr) bool {
	return m.host.IsNeverBlock(addr)
}

// HandOver is what a stopped monitor passes to the one that replaces it.
type HandOver struct {
	// History is the detection history, for ReadoptHistory.
	History []Detection
	// Blocks are the blocks that were in force, for Readopt. Stop releases
	// them; only a rebuild of the monitor puts them back.
	Blocks []BlockedSource
}

// StopAndHandOver stops the monitor and returns its history and its blocks,
// for the next monitor to take over. Both are read after Stop has handled
// the detections still queued, which it records and, under the policy auto,
// may block: read before, they would be lost.
func (m *Monitor) StopAndHandOver() HandOver {
	held := m.stopHolding()
	return HandOver{History: m.History(), Blocks: held}
}

// History returns the history, so a caller rebuilding the monitor can hand it
// to the new one. See ReadoptHistory.
func (m *Monitor) History() []Detection {
	all, _ := m.history.List(-1)
	return all
}

// ReconcileHistory corrects, after the blocks of a previous monitor were
// readopted, the entries that say "blocked" for an address this monitor did
// not block again because it is now on the never-block list: shown as an
// expired block, they would describe a block that ended on its own.
func (m *Monitor) ReconcileHistory() {
	all, _ := m.history.List(-1)
	for _, d := range all {
		if d.Status == StatusBlocked && !m.IsBlocked(d.Addr) && m.IsExempt(d.Addr) {
			m.history.SetStatus(d.Addr, StatusRefused, "the source is on the never-block list")
		}
	}
}

// ReadoptHistory takes over the history of a previous monitor. Questions that
// were open are reported unanswered: the new monitor did not ask them.
func (m *Monitor) ReadoptHistory(entries []Detection) {
	for i := range entries {
		if entries[i].Status == StatusAsked {
			entries[i].Status = StatusUnanswered
		}
	}
	m.history.Readopt(entries)
}

// BlockInfo returns the block on addr and the firewall objects that apply it,
// read from the firewall. ok is false when addr is not blocked. A firewall that
// cannot be read, or no longer holds the address, is reported in ruleErr and
// does not hide the block: the user is looking at it because something seems
// wrong.
func (m *Monitor) BlockInfo(addr netip.Addr) (src BlockedSource, rule string, ruleErr error, ok bool) {
	if m.blocks == nil {
		return BlockedSource{}, "", nil, false
	}
	src, ok = m.blocks.Lookup(addr)
	if !ok {
		return BlockedSource{}, "", nil, false
	}
	rule, ruleErr = m.blocks.Describe(src.Addr)
	return src, rule, ruleErr, true
}

// Blocked lists the active blocks.
func (m *Monitor) Blocked() []BlockedSource {
	if m.blocks == nil {
		return nil
	}
	return m.blocks.Blocked()
}

// BlockedFirst is Blocked bounded to limit entries, with the total count.
func (m *Monitor) BlockedFirst(limit int) ([]BlockedSource, int) {
	if m.blocks == nil {
		return nil, 0
	}
	return m.blocks.BlockedFirst(limit)
}

// Stats returns the engine counters.
func (m *Monitor) Stats() Stats { return m.engine.Stats() }

// Config returns the effective configuration, which may differ from the one
// requested if an enforcement backend was unavailable.
func (m *Monitor) Config() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// Blocks is Blocked. A rebuild of the monitor takes its blocks from
// StopAndHandOver instead, read after the queued detections are handled.
func (m *Monitor) Blocks() []BlockedSource { return m.Blocked() }

// Readopt re-applies blocks held by a previous monitor, with the time they had
// left. It is a no-op when blocking is disabled.
func (m *Monitor) Readopt(sources []BlockedSource) {
	if m.blocks == nil || len(sources) == 0 {
		return
	}
	m.blocks.Readopt(sources)
}
