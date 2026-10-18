//go:build linux

package portscan

import (
	"container/list"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Blocker installs and removes the firewall rule that actually stops a
// scanner's traffic.
//
// It is an interface so the manager can be tested without touching the
// machine's firewall, and so the enforcement mechanism can be replaced without
// touching the policy that decides when to block.
type Blocker interface {
	// Block starts dropping inbound traffic from addr.
	Block(addr netip.Addr) error
	// Unblock stops dropping it. It must be idempotent: releasing a block that
	// is already gone is not an error.
	Unblock(addr netip.Addr) error
	// Close removes everything the backend installed, including objects that
	// are not per-address, so nothing outlives the daemon. It must be idempotent.
	Close() error
}

// ManyUnblocker is an optional Blocker that releases several addresses in one
// transaction. Each nftables operation is a netlink round trip, and the commit
// is serialised per network namespace, so releasing a hundred addresses one by
// one takes the whole machine's firewall with it for most of a second; batched,
// a few milliseconds. The batch is all-or-nothing at the backend and idempotent,
// since the kernel-side timeout may have won the race. Callers fall back to
// Unblock per address for a backend without it.
type ManyUnblocker interface {
	UnblockMany(addrs []netip.Addr) error
}

// Repairer is an optional Blocker that can tell its firewall objects were
// removed behind its back and put them back, with every block in force. It
// reports whether it had to.
type Repairer interface {
	Repair() (bool, error)
}

// Describer is an optional Blocker that can show the firewall objects that
// apply a block, read back from the firewall rather than recalled.
type Describer interface {
	Describe(addr netip.Addr) (string, error)
}

// blockEntry is one active block.
type blockEntry struct {
	addr      netip.Addr
	expiresAt time.Time
	// blockedAt is when the block was installed or last extended, which is
	// the order of the list; the user interface lists blocks and detections
	// together by it.
	blockedAt time.Time
	reason    string
	// scan is the detection that led to the block, nil when none is known (a
	// block confirmed for a source the history no longer holds). It is what the user
	// interface shows when asked why the address is blocked: the alert itself
	// is a notification, long gone by the time anyone looks at the list.
	scan *ScanEvent
	elem *list.Element
	// releaseFailed records that the backend refused to take this address back
	// out of the firewall. The entry is kept so the next expiry pass retries it
	// and so the cap keeps counting what is really installed.
	releaseFailed bool
}

// BlockManager owns the set of blocked sources and their expiry. The daemon owns
// it, not the GUI: a GUI-installed rule would outlive the GUI, and a headless
// node would have no enforcement. Three properties are not negotiable:
//
//   - blocks expire (PortSentry's blocked file never does);
//   - the number of simultaneous blocks is capped, oldest evicted, so one
//     nmap -D with a hundred decoys cannot install a hundred rules;
//   - an address the host must never block cannot be blocked, whatever the
//     caller asks (psad added this after the fact, psad:7209-7227).
type BlockManager struct {
	mu       sync.Mutex
	blocker  Blocker
	byAddr   map[netip.Addr]*blockEntry
	order    *list.List // front = most recently blocked
	maxCount int
	duration time.Duration

	// isExempt reports addresses that must never be blocked.
	isExempt func(netip.Addr) bool

	onError func(error)
	now     func() time.Time

	stop    chan struct{}
	stopped bool
	// repairFailing records that the last Repair failed, so a failure that
	// lasts is reported once and not every expiry pass.
	repairFailing bool
	// overcap records that the backend left the firewall holding more addresses
	// than maxCount and refused to correct it. See Block.
	overcap bool
}

// NewBlockManager builds a manager. isExempt must not be nil: without it there
// is nothing preventing the host from blocking its own gateway.
func NewBlockManager(b Blocker, cfg BlockConfig, isExempt func(netip.Addr) bool) (*BlockManager, error) {
	if b == nil {
		return nil, fmt.Errorf("portscan: a Blocker is required")
	}
	if isExempt == nil {
		return nil, fmt.Errorf("portscan: an exemption predicate is required; without one the host can block its own gateway")
	}
	if cfg.Duration <= 0 {
		return nil, fmt.Errorf("portscan: Block.Duration must be greater than 0")
	}
	if cfg.MaxBlockedSources < 1 {
		return nil, fmt.Errorf("portscan: Block.MaxBlockedSources must be at least 1")
	}
	return &BlockManager{
		blocker:  b,
		byAddr:   make(map[netip.Addr]*blockEntry, cfg.MaxBlockedSources),
		order:    list.New(),
		maxCount: cfg.MaxBlockedSources,
		duration: cfg.Duration,
		isExempt: isExempt,
		now:      time.Now,
		stop:     make(chan struct{}),
	}, nil
}

// ErrExempt is returned when the caller asks to block an address that the host
// must never block.
var ErrExempt = fmt.Errorf("portscan: refusing to block an exempt address")

// Block installs a time-limited block for addr. It refuses exempt addresses
// with an error rather than a silent no-op, which would leave the user
// believing they were protected.
func (m *BlockManager) Block(addr netip.Addr, reason string) error {
	return m.BlockScan(addr, reason, nil)
}

// BlockScan is Block, keeping scan as the detection behind the block. scan may
// be nil. It is not copied: a ScanEvent is not modified once emitted.
func (m *BlockManager) BlockScan(addr netip.Addr, reason string, scan *ScanEvent) error {
	addr = normalizeAddr(addr)
	if !addr.IsValid() {
		return fmt.Errorf("portscan: invalid address")
	}
	if m.isExempt(addr) {
		return fmt.Errorf("%w: %s", ErrExempt, addr)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// A stopped manager has released everything and has no expiry loop, so a
	// block installed now would be one nobody owns. The check lives here, at the
	// bottom, where no late answer from a user interface can get past it.
	if m.stopped {
		return fmt.Errorf("portscan: the block manager is stopped")
	}
	if m.overcap {
		return fmt.Errorf("portscan: the firewall holds more than MaxBlockedSources (%d)"+
			" and the backend refused to correct it; refusing to install more", m.maxCount)
	}

	now := m.now()
	if e, ok := m.byAddr[addr]; ok {
		// Already blocked: extend rather than install a second rule.
		e.reason = reason
		if scan != nil {
			e.scan = scan
		}
		if e.releaseFailed {
			// Except for an entry the backend refused to take back out: it is recorded
			// expired and at the back of the list so that it leaves first, and must not be
			// turned into the most recently used entry with a full duration ahead.
			return nil
		}
		// The firewall is told too: its own timeout, set when the address was
		// installed, would otherwise end the block before the manager does.
		if err := m.blocker.Block(addr); err != nil {
			return fmt.Errorf("portscan: extending the block for %s: %w", addr, err)
		}
		e.expiresAt = now.Add(m.duration)
		e.blockedAt = now
		m.order.MoveToFront(e.elem)
		return nil
	}

	// Install first, evict only on success: the other order loses a real block for
	// every backend error, and a broken backend at the cap would empty the table,
	// at a rate forged sources choose.
	if err := m.blocker.Block(addr); err != nil {
		return fmt.Errorf("portscan: installing a block for %s: %w", addr, err)
	}
	if len(m.byAddr) >= m.maxCount {
		if err := m.evictOldestLocked(); err != nil {
			// Room could not be made, so keeping this one would put more
			// addresses in the firewall than MaxBlockedSources allows -- the
			// bound that limits the self-inflicted damage of a decoy or
			// spoofed-source scan. It is taken straight back out.
			m.reportLocked(err)
			if rerr := m.blocker.Unblock(addr); rerr != nil {
				// Neither the old address nor the new one could be removed. The firewall is one
				// over the cap and this manager cannot correct it, so it stops installing until
				// something succeeds; otherwise every attempt would add another.
				m.overcap = true

				// Record the entry anyway, expired and at the back of the list, where eviction
				// and ExpireDue look first: this is the address that should not be in the
				// firewall. Dropping it would leave it installed and known to nobody -- not
				// listed, not retried, not released at shutdown -- and the cap would stop
				// counting what is really installed.
				e := &blockEntry{
					addr: addr, expiresAt: now, blockedAt: now, reason: reason, scan: scan,
					releaseFailed: true,
				}
				e.elem = m.order.PushBack(e)
				m.byAddr[addr] = e

				m.reportLocked(degraded("%s was installed and could not be taken"+
					" back out after eviction failed; the firewall is above"+
					" MaxBlockedSources (%d) and no further blocks will be installed"+
					" until a release succeeds: %w", addr, m.maxCount, rerr))
			}
			return fmt.Errorf("portscan: refusing to exceed MaxBlockedSources (%d): %w",
				m.maxCount, err)
		}
	}
	e := &blockEntry{addr: addr, expiresAt: now.Add(m.duration), blockedAt: now, reason: reason, scan: scan}
	e.elem = m.order.PushFront(e)
	m.byAddr[addr] = e
	return nil
}

// Unblock releases a block early.
func (m *BlockManager) Unblock(addr netip.Addr) error {
	addr = normalizeAddr(addr)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unblockLocked(addr)
}

// unblockLocked releases a block, and forgets it only if the backend agreed.
// Forgetting it first would leave a failed release dropped by the firewall and
// known to nobody, and would unbind MaxBlockedSources, whose purpose is to bound
// a decoy scan's damage. Kept, it is retried on the next ExpireDue pass.
func (m *BlockManager) unblockLocked(addr netip.Addr) error {
	e, ok := m.byAddr[addr]
	if !ok {
		return nil
	}
	if err := m.blocker.Unblock(addr); err != nil {
		e.releaseFailed = true
		// A rule left in the user's firewall that this daemon can no longer
		// remove is a degradation by any reading, and the one the user most
		// needs to hear about: nothing else in the system will mention it.
		return degraded("releasing the block for %s: %w", addr, err)
	}
	m.order.Remove(e.elem)
	delete(m.byAddr, addr)
	// A release that worked means the backend is answering again, so the refusal
	// above lifts.
	m.overcap = false
	return nil
}

// releaseManyLocked asks the backend to drop several addresses in one
// transaction, when it can, does the bookkeeping for what the batch released,
// and returns how many that was. The caller's per-address pass handles the
// rest -- a backend with no batch API, a single entry, a failed batch -- and is
// what applies the "forget only if the backend agreed" rule and reports failures.
func (m *BlockManager) releaseManyLocked(entries []*blockEntry) int {
	if len(entries) < 2 {
		return 0 // one address is already one transaction
	}
	many, ok := m.blocker.(ManyUnblocker)
	if !ok {
		return 0
	}
	addrs := make([]netip.Addr, 0, len(entries))
	for _, e := range entries {
		addrs = append(addrs, e.addr)
	}
	if err := many.UnblockMany(addrs); err != nil {
		// Nothing is forgotten and nothing is reported here: the per-address
		// pass that follows retries each one and reports whatever genuinely
		// failed, with the address in the message. Reporting twice would double
		// every shutdown's output.
		return 0
	}
	// The bookkeeping is done here for everything the batch released: left to the
	// per-address pass, which looks the address up first, it would repeat a netlink
	// round trip for each of them.
	for _, e := range entries {
		m.order.Remove(e.elem)
		delete(m.byAddr, e.addr)
	}
	// A release that worked means the backend is answering again.
	m.overcap = false
	return len(entries)
}

// evictOldestLocked releases the oldest block to make room, and reports whether
// it managed to.
func (m *BlockManager) evictOldestLocked() error {
	back := m.order.Back()
	if back == nil {
		return nil
	}
	return m.unblockLocked(back.Value.(*blockEntry).addr)
}

// reportLocked hands an error to the daemon; m.mu must be held. The errors it
// carries are all of one kind -- the daemon failed to undo something it did to
// the user's firewall -- and must reach someone.
func (m *BlockManager) reportLocked(err error) {
	if err == nil || m.onError == nil {
		return
	}
	m.onError(err)
}

// ExpireDue releases every block whose time has come, and every block on an
// address that has since become exempt, and returns how many were released.
// Exemption is checked at install time against a snapshot up to a refresh
// interval old; a block installed on the gateway during a DHCP renewal must not
// last hours after the snapshot says again that it is the gateway. Rechecking
// here bounds it to one expiry pass. It only ever releases.
func (m *BlockManager) ExpireDue() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()

	// `nft flush ruleset`, which `systemctl restart nftables` runs, removes the
	// backend's objects and every block with them. Block rebuilds them when it
	// meets the gap, but only a new block gets there: until then every scanner
	// listed as blocked would be free to come back, and reported "blocked" when
	// it did. Checked here, the gap lasts one expiry pass.
	if r, ok := m.blocker.(Repairer); ok {
		_, err := r.Repair()
		if err != nil && !m.repairFailing {
			m.reportLocked(err)
		}
		m.repairFailing = err != nil
	}

	// Release everything due in one transaction where the backend can; the loop
	// below handles the remainder, applies the "forget only if the backend agreed"
	// rule and reports failures. The lock stays held across the batch, so Block
	// cannot extend an entry halfway through being released; the packet path does
	// not call this manager (see Monitor.onProbe).
	var due []*blockEntry
	for _, e := range m.blockedSnapshotLocked() {
		if !now.Before(e.expiresAt) || m.isExempt(e.addr) {
			due = append(due, e)
		}
	}
	n := m.releaseManyLocked(due)

	for _, e := range m.blockedSnapshotLocked() {
		if !now.Before(e.expiresAt) || m.isExempt(e.addr) {
			if err := m.unblockLocked(e.addr); err != nil {
				// Kept, so this pass retries it in thirty seconds and the cap
				// keeps counting what is really installed. Reported, because an
				// address the daemon believes it released and the firewall is
				// still dropping is exactly what nobody would otherwise notice.
				m.reportLocked(err)
				continue
			}
			n++
		}
	}
	return n
}

func (m *BlockManager) blockedSnapshotLocked() []*blockEntry {
	out := make([]*blockEntry, 0, len(m.byAddr))
	for _, e := range m.byAddr {
		out = append(out, e)
	}
	return out
}

// Start runs the expiry loop.
func (m *BlockManager) Start(interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-t.C:
				m.ExpireDue()
			}
		}
	}()
}

// Stop ends the expiry loop and releases every block: a block that outlives
// the process that created it is a rule nobody owns and nobody will remove.
func (m *BlockManager) Stop() {
	m.mu.Lock()
	if !m.stopped {
		m.stopped = true
		close(m.stop)
	}
	// One transaction for the whole set where the backend allows it; anything the
	// batch could not release falls through to the per-address path, which reports
	// the failures. A configuration reload runs this too.
	m.releaseManyLocked(m.blockedSnapshotLocked())

	var failed []error
	for _, e := range m.blockedSnapshotLocked() {
		if err := m.unblockLocked(e.addr); err != nil {
			// Said out loud: shutting down while leaving an address dropped by the
			// firewall is the worst thing this manager can do quietly. The kernel-side
			// timeout still ends it, but the user has to be able to learn it is there.
			failed = append(failed, err)
		}
	}
	for _, err := range failed {
		m.reportLocked(err)
	}
	// Releasing every element is not enough: the backend also owns objects that
	// belong to no address -- a table, a chain in the input hook, two rules --
	// and those survive the process unless it is told to remove them.
	err := m.blocker.Close()
	m.mu.Unlock()
	if err != nil && m.onError != nil {
		m.onError(err)
	}
}

// SetOnError registers a callback for failures that have nowhere else to go,
// such as a backend that could not be torn down.
func (m *BlockManager) SetOnError(f func(error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onError = f
}

// IsBlocked reports whether addr is currently blocked.
func (m *BlockManager) IsBlocked(addr netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.byAddr[normalizeAddr(addr)]
	return ok
}

// BlockedSource is one entry of the public listing.
type BlockedSource struct {
	Addr      netip.Addr
	ExpiresAt time.Time
	// BlockedAt is when the block was installed or last extended; zero when
	// unknown.
	BlockedAt time.Time
	Reason    string
	// ReleaseFailed marks an address the firewall refused to take back: its
	// expiry has passed and it is still installed. Shown as "expiring", it
	// would look like the one entry about to go on its own, when it is the
	// one that will not.
	ReleaseFailed bool
	// Scan is the detection that led to the block, or nil.
	Scan *ScanEvent
}

// Blocked returns the current blocks, most recent first.
func (m *BlockManager) Blocked() []BlockedSource {
	out, _ := m.BlockedFirst(-1)
	return out
}

// BlockedFirst returns at most limit blocks, most recent first, and how many
// there are in all; a negative limit means all of them. The GUI is sent
// 512 of up to 65536, and copying the rest under this lock on every
// refresh would be work done for nobody.
func (m *BlockManager) BlockedFirst(limit int) ([]BlockedSource, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := len(m.byAddr)
	n := total
	if limit >= 0 && limit < n {
		n = limit
	}
	out := make([]BlockedSource, 0, n)
	for el := m.order.Front(); el != nil && len(out) < n; el = el.Next() {
		e := el.Value.(*blockEntry)
		out = append(out, e.source())
	}
	return out, total
}

// source is the entry as callers outside the manager see it.
func (e *blockEntry) source() BlockedSource {
	return BlockedSource{Addr: e.addr, ExpiresAt: e.expiresAt, BlockedAt: e.blockedAt,
		Reason: e.reason, ReleaseFailed: e.releaseFailed, Scan: e.scan}
}

// Describe shows the firewall objects that apply the block on addr, when the
// backend can read them back.
func (m *BlockManager) Describe(addr netip.Addr) (string, error) {
	d, ok := m.blocker.(Describer)
	if !ok {
		return "", fmt.Errorf("portscan: this firewall backend cannot show its rules")
	}
	return d.Describe(normalizeAddr(addr))
}

// UpdateScan replaces the scan kept with the block on addr, if there is a
// block and scan is not nil. The expiry is left alone: a detection while
// blocked does not extend the block.
func (m *BlockManager) UpdateScan(addr netip.Addr, scan *ScanEvent) {
	if scan == nil {
		return
	}
	addr = normalizeAddr(addr)
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.byAddr[addr]; ok {
		e.scan = scan
	}
}

// Lookup returns the block on addr, if there is one.
func (m *BlockManager) Lookup(addr netip.Addr) (BlockedSource, bool) {
	addr = normalizeAddr(addr)
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byAddr[addr]
	if !ok {
		return BlockedSource{}, false
	}
	return e.source(), true
}

// Readopt reinstalls blocks that an earlier instance of this manager held, with
// the time they had left: a configuration reload tears detection down, and an
// unrelated edit must not unblock every scanner.
//
// The remaining time is carried, not restarted, so a reload cannot extend a
// block, and is cut to the new Block.Duration when that is shorter -- the kernel
// element gets the new backend's timeout, and the manager must not claim a
// block the kernel has released. Addresses whose time has run out are skipped,
// and exemption is re-checked: a reload is when an operator adds the address
// that just cut them off.
//
// sources is newest first, as Blocked returns it, and is replayed oldest
// first so the order survives: each block goes to the front. Replayed as
// given, a reload would reverse it, and the cap would then release the
// newest.
func (m *BlockManager) Readopt(sources []BlockedSource) {
	now := m.now()
	for i := len(sources) - 1; i >= 0; i-- {
		s := sources[i]
		until := s.ExpiresAt
		if limit := now.Add(m.duration); until.After(limit) {
			until = limit
		}
		if !until.After(now) {
			continue
		}
		if m.isExempt(s.Addr) {
			continue
		}
		if err := m.blockUntil(s.Addr, s.Reason, s.Scan, until, s.BlockedAt); err != nil {
			m.mu.Lock()
			m.reportLocked(fmt.Errorf("portscan: could not re-apply the block for %s"+
				" across a configuration reload: %w", s.Addr, err))
			m.mu.Unlock()
		}
	}
}

// blockUntil is Block with an explicit expiry, for Readopt, keeping the time
// the block was installed when it is known: a reload is not a new block.
func (m *BlockManager) blockUntil(addr netip.Addr, reason string, scan *ScanEvent, until, blockedAt time.Time) error {
	if err := m.BlockScan(addr, reason, scan); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.byAddr[normalizeAddr(addr)]; ok {
		e.expiresAt = until
		if !blockedAt.IsZero() {
			e.blockedAt = blockedAt
		}
	}
	return nil
}
