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

// fakeBlocker records what would have been done to the firewall.
type fakeBlocker struct {
	mu       sync.Mutex
	active   map[netip.Addr]bool
	blocks   int
	unblocks int
	failNext error
	closes   int
	closeErr error
}

func newFakeBlocker() *fakeBlocker {
	return &fakeBlocker{active: map[netip.Addr]bool{}}
}

func (f *fakeBlocker) Block(a netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	f.active[a] = true
	f.blocks++
	return nil
}

func (f *fakeBlocker) Unblock(a netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.active, a)
	f.unblocks++
	return nil
}

func (f *fakeBlocker) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.active)
}

func (f *fakeBlocker) isActive(a netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active[a]
}

// newTestBlockManager builds a manager with a controllable clock.
func newTestBlockManager(t *testing.T, b Blocker, cfg BlockConfig, exempt func(netip.Addr) bool) (*BlockManager, *time.Time) {
	t.Helper()
	m, err := NewBlockManager(b, cfg, exempt)
	if err != nil {
		t.Fatalf("NewBlockManager: %v", err)
	}
	now := time.Unix(1700000000, 0)
	m.now = func() time.Time { return now }
	return m, &now
}

func testBlockConfig() BlockConfig {
	c := DefaultConfig().Block
	c.Policy = BlockAuto
	return c
}

// TestBlockManagerRefusesExemptAddress is the guarantee that matters most.
//
// psad shipped without it and had to add auto_block_ignore_ip() afterwards
// (ChangeLog:1111). The check must live here, below every caller, so that no
// path -- an automatic decision, a message from the GUI, a future caller
// nobody has written yet -- can bypass it.
func TestBlockManagerRefusesExemptAddress(t *testing.T) {
	fb := newFakeBlocker()
	gateway := netip.MustParseAddr("192.0.2.254")
	exempt := func(a netip.Addr) bool { return a == gateway }
	m, _ := newTestBlockManager(t, fb, testBlockConfig(), exempt)

	err := m.Block(gateway, "decoy scan")
	if err == nil {
		t.Fatal("blocking an exempt address succeeded")
	}
	if !errors.Is(err, ErrExempt) {
		t.Errorf("error = %v, want it to wrap ErrExempt", err)
	}
	if fb.blocks != 0 {
		t.Errorf("the firewall was touched %d time(s) for an exempt address", fb.blocks)
	}
	// The refusal must be loud, not a silent no-op: a caller that believes it
	// blocked something when it did not leaves the user believing they are
	// protected.
	if fb.isActive(gateway) {
		t.Error("the exempt address ended up blocked")
	}
}

// TestBlockManagerRequiresExemptionPredicate refuses to build a manager that
// could block anything at all.
func TestBlockManagerRequiresExemptionPredicate(t *testing.T) {
	if _, err := NewBlockManager(newFakeBlocker(), testBlockConfig(), nil); err == nil {
		t.Fatal("NewBlockManager accepted a nil exemption predicate")
	}
	if _, err := NewBlockManager(nil, testBlockConfig(), func(netip.Addr) bool { return false }); err == nil {
		t.Fatal("NewBlockManager accepted a nil Blocker")
	}
}

// TestBlockManagerCapIsEnforced is the defence against a decoy or
// spoofed-source scan. nmap -D carries up to a hundred forged sources, every
// one of which genuinely crosses the detection threshold; without a cap that
// is a hundred firewall rules installed on an attacker's command.
// failingUnblocker installs blocks but refuses to release them, which is what a
// real backend does under load: NftBlocker.Unblock returns an error whenever the
// netlink Flush fails for anything other than ENOENT -- ENOBUFS on the socket, a
// concurrent nftables transaction, an `nft -f` committing at the same moment. An
// attacker flooding does not have to cause the error, only make it likely.
type failingUnblocker struct {
	*fakeBlocker
	fail bool
}

func (f *failingUnblocker) Unblock(a netip.Addr) error {
	if f.fail {
		return errors.New("netlink: no buffer space available")
	}
	return f.fakeBlocker.Unblock(a)
}

// TestFailedReleaseKeepsTheBlockAccountedFor: a release the firewall refused
// must not make the daemon forget the address.
//
// An unblockLocked that removed the entry from byAddr and order BEFORE calling
// the backend, and restored nothing on failure, would leave the address
// dropped by the firewall and known to nobody, all the more so if its callers
// discarded the error and nothing in the daemon called
// BlockManager.SetOnError: Blocked() would not list it, Stop would not target
// it, the user could not see it.
func TestFailedReleaseKeepsTheBlockAccountedFor(t *testing.T) {
	b := &failingUnblocker{fakeBlocker: newFakeBlocker()}
	var reported []error
	m, err := NewBlockManager(b, BlockConfig{Duration: time.Hour, MaxBlockedSources: 8},
		func(netip.Addr) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	m.SetOnError(func(e error) { reported = append(reported, e) })

	addr := netip.MustParseAddr("198.51.100.20")
	if err := m.Block(addr, "scan"); err != nil {
		t.Fatalf("Block: %v", err)
	}

	b.fail = true
	if err := m.Unblock(addr); err == nil {
		t.Fatal("Unblock reported success while the backend refused")
	}
	if !m.IsBlocked(addr) {
		t.Fatal("the daemon forgot an address the firewall is still dropping")
	}
	if !b.isActive(addr) {
		t.Fatal("the test double did not keep the block; the test proves nothing")
	}

	// Once the backend recovers, the address really is released.
	b.fail = false
	if err := m.Unblock(addr); err != nil {
		t.Fatalf("Unblock after the backend recovered: %v", err)
	}
	if m.IsBlocked(addr) || b.isActive(addr) {
		t.Fatal("the block survived a successful release")
	}
}

// TestFailedReleaseDoesNotUnboundTheCap: MaxBlockedSources exists to bound the
// self-inflicted damage of a decoy or spoofed-source scan. An eviction that
// believed it had made room when the release failed would let the firewall
// accumulate -- measured that way, with a cap of two: the manager listed 2,
// the firewall dropped 6.
func TestFailedReleaseDoesNotUnboundTheCap(t *testing.T) {
	b := &failingUnblocker{fakeBlocker: newFakeBlocker(), fail: true}
	const maxBlocks = 2
	var reported []error
	m, err := NewBlockManager(b, BlockConfig{Duration: time.Hour, MaxBlockedSources: maxBlocks},
		func(netip.Addr) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	m.SetOnError(func(e error) { reported = append(reported, e) })

	installed := 0
	for i := 0; i < 6; i++ {
		addr := netip.AddrFrom4([4]byte{198, 51, 100, byte(30 + i)})
		if err := m.Block(addr, "scan"); err == nil {
			installed++
		}
	}

	inFirewall := b.count()
	t.Logf("cap=%d: %d Block calls succeeded, manager lists %d, firewall drops %d, %d errors reported",
		maxBlocks, installed, len(m.Blocked()), inFirewall, len(reported))

	// cap+1 is the floor, not cap: a block is installed before room is made for
	// it, because making room first loses a live block every time the install
	// then fails -- and with an all-failing backend that empties the table. So
	// one address can get in before the manager discovers it cannot evict, and
	// cannot be taken back out either. What must not happen is a SECOND one: the
	// manager stops installing until a release succeeds. Without that stop, a
	// cap of two held six.
	if inFirewall > maxBlocks+1 {
		t.Errorf("the firewall is dropping %d addresses for a cap of %d: the bound that"+
			" limits a decoy scan's self-inflicted damage is not holding", inFirewall, maxBlocks)
	}
	// The manager must list that extra address, not hide it. Dropping it on the
	// floor would keep Blocked() within the cap while the firewall was not,
	// which bounds a single episode and nothing more: the address would be in
	// the firewall and known to nobody, so ExpireDue would never retry it, Stop
	// would never target it, and ReleaseBlock on it would do nothing. Each
	// later episode would leave another.
	if len(m.Blocked()) > maxBlocks+1 {
		t.Errorf("the manager lists %d blocks for a cap of %d", len(m.Blocked()), maxBlocks)
	}
	if len(m.Blocked()) != inFirewall {
		t.Errorf("the manager lists %d blocks but the firewall drops %d: an address the"+
			" user can neither see nor release", len(m.Blocked()), inFirewall)
	}
	if len(reported) == 0 {
		t.Error("nothing was reported: the daemon could not say it failed to release a block")
	}

	// And it recovers: once the backend answers again, the refusal lifts.
	b.fail = false
	if n := m.ExpireDue(); n >= 0 {
		_ = n
	}
	if err := m.Unblock(netip.AddrFrom4([4]byte{198, 51, 100, 30})); err != nil {
		t.Fatalf("Unblock after the backend recovered: %v", err)
	}
	if err := m.Block(netip.MustParseAddr("198.51.100.99"), "scan"); err != nil {
		t.Fatalf("the manager stayed refusing after a successful release: %v", err)
	}

	// And it CONVERGES: the over-cap address is expired and sits at the back of
	// the list, so the first expiry pass with a working backend takes it out.
	// This is what makes the bound survive a sequence of episodes rather than
	// just one.
	m.ExpireDue()
	if n := b.count(); n > maxBlocks {
		t.Errorf("after the backend recovered the firewall still drops %d addresses"+
			" for a cap of %d: the over-cap address was never reclaimed", n, maxBlocks)
	}
}

func TestBlockManagerCapIsEnforced(t *testing.T) {
	fb := newFakeBlocker()
	cfg := testBlockConfig()
	cfg.MaxBlockedSources = 8
	m, _ := newTestBlockManager(t, fb, cfg, func(netip.Addr) bool { return false })

	for i := 0; i < 200; i++ {
		addr := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
		if err := m.Block(addr, "scan"); err != nil {
			t.Fatalf("Block(%v): %v", addr, err)
		}
	}
	if got := len(m.Blocked()); got != cfg.MaxBlockedSources {
		t.Errorf("active blocks = %d, want the cap of %d", got, cfg.MaxBlockedSources)
	}
	if got := fb.count(); got != cfg.MaxBlockedSources {
		t.Errorf("firewall entries = %d, want the cap of %d", got, cfg.MaxBlockedSources)
	}
	// The oldest must have been released, not merely forgotten: a rule that is
	// dropped from our bookkeeping but left in the firewall is a block nobody
	// owns and nobody will remove.
	if fb.isActive(netip.AddrFrom4([4]byte{198, 51, 100, 0})) {
		t.Error("the evicted block was left installed in the firewall")
	}
}

func TestBlockManagerExpiry(t *testing.T) {
	fb := newFakeBlocker()
	cfg := testBlockConfig()
	cfg.Duration = 4 * time.Hour
	m, clock := newTestBlockManager(t, fb, cfg, func(netip.Addr) bool { return false })

	addr := netip.MustParseAddr("192.0.2.66")
	if err := m.Block(addr, "scan"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !m.IsBlocked(addr) {
		t.Fatal("the address is not blocked right after blocking it")
	}

	*clock = clock.Add(3 * time.Hour)
	if n := m.ExpireDue(); n != 0 {
		t.Errorf("%d block(s) expired after 3h of a 4h block", n)
	}
	if !m.IsBlocked(addr) {
		t.Error("the block was released early")
	}

	*clock = clock.Add(2 * time.Hour) // now 5h in
	if n := m.ExpireDue(); n != 1 {
		t.Errorf("%d block(s) expired after 5h of a 4h block, want 1", n)
	}
	if m.IsBlocked(addr) {
		t.Error("the block outlived its duration")
	}
	if fb.isActive(addr) {
		t.Error("the firewall entry outlived the block")
	}
}

// TestBlockManagerReblockExtends: a source that keeps scanning must have its
// block extended rather than a second rule installed for the same address,
// and the firewall told, or its own timeout would end the block first.
func TestBlockManagerReblockExtends(t *testing.T) {
	fb := newFakeBlocker()
	cfg := testBlockConfig()
	cfg.Duration = time.Hour
	m, clock := newTestBlockManager(t, fb, cfg, func(netip.Addr) bool { return false })

	addr := netip.MustParseAddr("192.0.2.66")
	_ = m.Block(addr, "first")
	*clock = clock.Add(50 * time.Minute)
	_ = m.Block(addr, "still scanning")

	if len(fb.active) != 1 || fb.blocks != 2 {
		t.Errorf("the firewall holds %d addresses after %d calls, want 1 address and the"+
			" extension passed on (2 calls)", len(fb.active), fb.blocks)
	}
	*clock = clock.Add(30 * time.Minute) // 80 min after the first block
	if n := m.ExpireDue(); n != 0 {
		t.Errorf("the block expired despite having been extended (%d expired)", n)
	}
	if !m.IsBlocked(addr) {
		t.Error("the extended block was released")
	}
}

// TestBlockManagerStopReleasesEverything: a block must not outlive the process
// that created it. PortSentry's documentation has to warn that its blocked
// file "will not reflect the current state of your system" precisely because
// it does not do this.
func TestBlockManagerStopReleasesEverything(t *testing.T) {
	fb := newFakeBlocker()
	m, _ := newTestBlockManager(t, fb, testBlockConfig(), func(netip.Addr) bool { return false })
	for i := 0; i < 5; i++ {
		_ = m.Block(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), "scan")
	}
	if fb.count() != 5 {
		t.Fatalf("firewall entries = %d, want 5", fb.count())
	}
	m.Stop()
	if got := fb.count(); got != 0 {
		t.Errorf("%d firewall entries survived shutdown", got)
	}
}

// TestBlockManagerReportsBackendFailure: if the firewall refuses, the caller
// must learn about it instead of being told the source is blocked.
func TestBlockManagerReportsBackendFailure(t *testing.T) {
	fb := newFakeBlocker()
	fb.failNext = fmt.Errorf("netlink refused")
	m, _ := newTestBlockManager(t, fb, testBlockConfig(), func(netip.Addr) bool { return false })

	addr := netip.MustParseAddr("192.0.2.66")
	if err := m.Block(addr, "scan"); err == nil {
		t.Fatal("Block reported success although the backend failed")
	}
	if m.IsBlocked(addr) {
		t.Error("the manager recorded a block that was never installed")
	}
}

func TestBlockManagerUnblockIsIdempotent(t *testing.T) {
	fb := newFakeBlocker()
	m, _ := newTestBlockManager(t, fb, testBlockConfig(), func(netip.Addr) bool { return false })
	addr := netip.MustParseAddr("192.0.2.66")
	if err := m.Unblock(addr); err != nil {
		t.Errorf("unblocking an address that was never blocked returned %v", err)
	}
	_ = m.Block(addr, "scan")
	if err := m.Unblock(addr); err != nil {
		t.Errorf("Unblock: %v", err)
	}
	if err := m.Unblock(addr); err != nil {
		t.Errorf("second Unblock returned %v, want nil", err)
	}
}

// TestBlockManagerIPv6 checks both families reach the backend.
func TestBlockManagerIPv6(t *testing.T) {
	fb := newFakeBlocker()
	m, _ := newTestBlockManager(t, fb, testBlockConfig(), func(netip.Addr) bool { return false })
	v6 := netip.MustParseAddr("2001:db8::66")
	if err := m.Block(v6, "scan"); err != nil {
		t.Fatalf("Block(%v): %v", v6, err)
	}
	if !fb.isActive(v6) {
		t.Error("the IPv6 address did not reach the firewall backend")
	}
	if !m.IsBlocked(v6) {
		t.Error("IsBlocked is false for a blocked IPv6 address")
	}
}

// TestBlockManagerConcurrent exercises the locking under -race.
func TestBlockManagerConcurrent(t *testing.T) {
	fb := newFakeBlocker()
	cfg := testBlockConfig()
	cfg.MaxBlockedSources = 32
	m, _ := newTestBlockManager(t, fb, cfg, func(netip.Addr) bool { return false })

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				addr := netip.AddrFrom4([4]byte{10, byte(g), 0, byte(i)})
				_ = m.Block(addr, "scan")
				m.IsBlocked(addr)
				_ = m.Unblock(addr)
				m.Blocked()
				m.ExpireDue()
			}
		}(g)
	}
	wg.Wait()
}

// Close makes fakeBlocker satisfy the Blocker interface. It records the call so
// a test can require that the daemon actually tears the backend down: without
// a way to ask, the nftables table would survive every shutdown.
func (f *fakeBlocker) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return f.closeErr
}

func (f *fakeBlocker) closeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closes
}

// ---------------------------------------------------------------------------
// regression tests for the security properties
// ---------------------------------------------------------------------------

// TestStopClosesTheBackend: releasing every element is not enough. The backend
// also owns a table, a chain in the input hook and two rules, and nothing in
// the daemon could ask it to remove them because the interface had no Close.
// The table therefore survived every shutdown, and each restart appended two
// more rules -- sixteen after eight restarts, measured against a real kernel.
func TestStopClosesTheBackend(t *testing.T) {
	fb := newFakeBlocker()
	m, _ := newTestBlockManager(t, fb, testBlockConfig(), func(netip.Addr) bool { return false })

	if err := m.Block(netip.MustParseAddr("192.0.2.66"), "test"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	m.Stop()

	if fb.closeCount() != 1 {
		t.Fatalf("the backend was closed %d times, want 1", fb.closeCount())
	}
	if fb.count() != 0 {
		t.Fatalf("%d elements survived Stop", fb.count())
	}
}

// TestBlockAfterStopIsRefused: after Stop the expiry loop is gone and the
// release pass has already run, so a block installed now is one nobody owns and
// nobody removes -- for instance a PORTSCAN_BLOCK message arriving after the
// monitor had been stopped. The guard is here, at the
// bottom, so no caller can get past it.
func TestBlockAfterStopIsRefused(t *testing.T) {
	fb := newFakeBlocker()
	m, _ := newTestBlockManager(t, fb, testBlockConfig(), func(netip.Addr) bool { return false })
	m.Stop()

	err := m.Block(netip.MustParseAddr("192.0.2.66"), "late")
	if err == nil {
		t.Fatalf("a stopped manager accepted a block")
	}
	if !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("error = %v, want it to say the manager is stopped", err)
	}
	if fb.count() != 0 {
		t.Fatalf("the backend was asked to install a block after Stop")
	}
}

// TestFailedBlockDoesNotEvictALiveOne: eviction must not happen before the
// install. If it did, with the cap reached and the backend broken,
// MaxBlockedSources failed attempts would empty the table entirely --
// including the blocks that were protecting the host -- and an attacker with
// forged sources would choose how many attempts happened.
func TestFailedBlockDoesNotEvictALiveOne(t *testing.T) {
	fb := newFakeBlocker()
	cfg := testBlockConfig()
	cfg.MaxBlockedSources = 2
	m, _ := newTestBlockManager(t, fb, cfg, func(netip.Addr) bool { return false })

	a1 := netip.MustParseAddr("192.0.2.11")
	a2 := netip.MustParseAddr("192.0.2.12")
	for _, a := range []netip.Addr{a1, a2} {
		if err := m.Block(a, "real"); err != nil {
			t.Fatalf("Block(%s): %v", a, err)
		}
	}

	// The cap is reached. A failing install must cost nothing.
	fb.failNext = errors.New("nft: transaction failed")
	if err := m.Block(netip.MustParseAddr("192.0.2.13"), "attacker"); err == nil {
		t.Fatalf("the failing install reported success")
	}

	if !fb.isActive(a1) || !fb.isActive(a2) {
		t.Fatalf("a failed install evicted a live block: active=%v", fb.count())
	}
	if n := len(m.Blocked()); n != 2 {
		t.Fatalf("%d blocks tracked, want 2", n)
	}
}

// TestReblockRefreshesEvictionOrder: a re-blocked source moves to the front,
// so decoys filling the cap evict it last, not first.
func TestReblockRefreshesEvictionOrder(t *testing.T) {
	fb := newFakeBlocker()
	cfg := testBlockConfig()
	cfg.MaxBlockedSources = 2
	m, _ := newTestBlockManager(t, fb, cfg, func(netip.Addr) bool { return false })
	a := netip.MustParseAddr("198.51.100.1")
	b := netip.MustParseAddr("198.51.100.2")
	c := netip.MustParseAddr("198.51.100.3")
	for _, x := range []netip.Addr{a, b, a, c} {
		if err := m.Block(x, "scan"); err != nil {
			t.Fatalf("Block(%v): %v", x, err)
		}
	}
	if !fb.isActive(a) || fb.isActive(b) {
		t.Fatalf("after A, B, A again, C with a cap of 2: A active=%v B active=%v;"+
			" the re-blocked source must not be the one evicted", fb.isActive(a), fb.isActive(b))
	}
}

// repairingBlocker is a fakeBlocker whose objects can go missing.
type repairingBlocker struct {
	*fakeBlocker
	repairs int
	err     error
}

func (r *repairingBlocker) Repair() (bool, error) {
	r.repairs++
	return r.err == nil, r.err
}

// TestAFailingRepairIsReportedOnce: the expiry pass checks the firewall
// objects every thirty seconds. A rebuild that keeps failing -- another
// running instance holds the table -- is said once, not every pass, and said
// again if it fails anew after working.
func TestAFailingRepairIsReportedOnce(t *testing.T) {
	r := &repairingBlocker{fakeBlocker: newFakeBlocker(), err: errors.New("table held")}
	m, err := NewBlockManager(r, BlockConfig{Duration: time.Hour, MaxBlockedSources: 4},
		func(netip.Addr) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	reports := 0
	m.SetOnError(func(error) { reports++ })
	for i := 0; i < 5; i++ {
		m.ExpireDue()
	}
	if r.repairs != 5 || reports != 1 {
		t.Fatalf("5 passes: %d repairs, %d reports; want 5 and 1", r.repairs, reports)
	}
	r.err = nil
	m.ExpireDue()
	r.err = errors.New("table held again")
	m.ExpireDue()
	if reports != 2 {
		t.Fatalf("a failure after a working repair gave %d reports in all, want 2", reports)
	}
}

// readoptFrom blocks addrs in order, one minute apart, and hands what the
// manager holds to a new one with cap max, as a configuration reload does.
func readoptFrom(t *testing.T, addrs []string, max int) (*BlockManager, time.Time) {
	t.Helper()
	never := func(netip.Addr) bool { return false }
	cfg := BlockConfig{Duration: 4 * time.Hour, MaxBlockedSources: len(addrs)}
	old, err := NewBlockManager(newFakeBlocker(), cfg, never)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	for i, a := range addrs {
		old.now = func() time.Time { return base.Add(time.Duration(i) * time.Minute) }
		if err := old.Block(netip.MustParseAddr(a), "scan"); err != nil {
			t.Fatal(err)
		}
	}
	cfg.MaxBlockedSources = max
	m, err := NewBlockManager(newFakeBlocker(), cfg, never)
	if err != nil {
		t.Fatal(err)
	}
	reload := base.Add(time.Hour)
	m.now = func() time.Time { return reload }
	m.Readopt(old.Blocked())
	return m, reload
}

func blockedAddrs(m *BlockManager) string {
	var out []string
	for _, b := range m.Blocked() {
		out = append(out, b.Addr.String())
	}
	return strings.Join(out, " ")
}

// TestReadoptKeepsTheOrderOfBlocks: a Readopt that walked the blocks newest
// first and put each at the front would reverse them on a reload. At the cap,
// the next block would then release the most recent -- the scanner most
// likely still active -- and a lowered cap would keep the oldest.
func TestReadoptKeepsTheOrderOfBlocks(t *testing.T) {
	addrs := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	m, _ := readoptFrom(t, addrs, 3)
	if got, want := blockedAddrs(m), "198.51.100.3 198.51.100.2 198.51.100.1"; got != want {
		t.Fatalf("after a reload the blocks are [%s], want [%s]", got, want)
	}
	if err := m.Block(netip.MustParseAddr("198.51.100.4"), "scan"); err != nil {
		t.Fatal(err)
	}
	if got, want := blockedAddrs(m), "198.51.100.4 198.51.100.3 198.51.100.2"; got != want {
		t.Fatalf("a block at the cap after a reload left [%s], want [%s]", got, want)
	}
	m, _ = readoptFrom(t, addrs, 2)
	if got, want := blockedAddrs(m), "198.51.100.3 198.51.100.2"; got != want {
		t.Fatalf("a reload lowering the cap to 2 kept [%s], want the newest [%s]", got, want)
	}
}

// TestReadoptKeepsTheTimeLeft: a block carried across a reload keeps the time
// it had left, not a fresh duration: reloading the configuration must not be a
// way to extend every block.
func TestReadoptKeepsTheTimeLeft(t *testing.T) {
	m, reload := readoptFrom(t, []string{"198.51.100.1", "198.51.100.2"}, 2)
	for _, b := range m.Blocked() {
		// Blocked at 0 and 1 min for 4 h, reloaded at 60 min.
		want := 3 * time.Hour
		if b.Addr == netip.MustParseAddr("198.51.100.2") {
			want += time.Minute
		}
		if left := b.ExpiresAt.Sub(reload); left != want {
			t.Errorf("%s has %v left after the reload, want %v", b.Addr, left, want)
		}
	}
}

// TestBlockedFirstCountsWhatItLeavesOut: the list is bounded, and the total
// is what lets the window say how many blocks it does not show.
func TestBlockedFirstCountsWhatItLeavesOut(t *testing.T) {
	m, err := NewBlockManager(newFakeBlocker(), BlockConfig{Duration: time.Hour, MaxBlockedSources: 8},
		func(netip.Addr) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := m.Block(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), "scan"); err != nil {
			t.Fatal(err)
		}
	}
	for _, limit := range []int{2, 4} {
		if got, total := m.BlockedFirst(limit); len(got) != limit || total != 5 {
			t.Errorf("BlockedFirst(%d) gave %d of %d, want %d of 5", limit, len(got), total, limit)
		}
	}
}

// TestReadoptSkipsWhatHasRunOut: a block whose time ran out during the reload
// is not reinstalled, even until the next expiry pass.
func TestReadoptSkipsWhatHasRunOut(t *testing.T) {
	m, err := NewBlockManager(newFakeBlocker(), BlockConfig{Duration: time.Hour, MaxBlockedSources: 8},
		func(netip.Addr) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m.now = func() time.Time { return now }
	m.Readopt([]BlockedSource{{Addr: netip.MustParseAddr("198.51.100.1"), ExpiresAt: now.Add(-time.Second)}})
	if got := blockedAddrs(m); got != "" {
		t.Fatalf("a block that had run out was reinstalled: [%s]", got)
	}
}

// TestBlockedAtIsWhenTheBlockWasMade: the user interface lists blocks and
// detections together, most recent first, by when each block was made. An
// extension makes the block recent again, as it moves it to the front; a
// reload does not, since it is not a new block.
func TestBlockedAtIsWhenTheBlockWasMade(t *testing.T) {
	m, reload := readoptFrom(t, []string{"198.51.100.1", "198.51.100.2"}, 2)
	base := reload.Add(-time.Hour)
	for _, b := range m.Blocked() {
		want := base
		if b.Addr == netip.MustParseAddr("198.51.100.2") {
			want = base.Add(time.Minute)
		}
		if !b.BlockedAt.Equal(want) {
			t.Errorf("after a reload %s says blocked at %v, want %v", b.Addr, b.BlockedAt, want)
		}
	}
	later := reload.Add(time.Minute)
	m.now = func() time.Time { return later }
	if err := m.Block(netip.MustParseAddr("198.51.100.1"), "scan"); err != nil {
		t.Fatal(err)
	}
	got := m.Blocked()
	if got[0].Addr != netip.MustParseAddr("198.51.100.1") || !got[0].BlockedAt.Equal(later) {
		t.Errorf("an extended block is %s at %v first, want 198.51.100.1 at %v",
			got[0].Addr, got[0].BlockedAt, later)
	}
}
