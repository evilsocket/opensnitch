//go:build linux

package portscan

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

// These tests install real nftables objects, which needs CAP_NET_ADMIN in the
// current network namespace. testdata/run_nft_test.sh provides both by
// re-running the package inside `unshare -Urn`.
//
// They are skipped when that is not available, unless PORTSCAN_REQUIRE_NFT=1 is
// set -- which is how the runner and CI insist that the check actually ran
// rather than quietly skipping, the failure mode that turns a conditional skip
// into a permanent no-op.

// requireNft skips or fails depending on PORTSCAN_REQUIRE_NFT.
func requireNft(t *testing.T, reason string, err error) {
	t.Helper()
	if os.Getenv("PORTSCAN_REQUIRE_NFT") == "1" {
		t.Fatalf("PORTSCAN_REQUIRE_NFT=1 but %s: %v", reason, err)
	}
	t.Skipf("%s: %v (run testdata/run_nft_test.sh for the real thing)", reason, err)
}

// newLiveBlocker builds an NftBlocker or skips the test.
func newLiveBlocker(t *testing.T, d time.Duration) *NftBlocker {
	t.Helper()
	requireDisposableNetwork(t, "PORTSCAN_REQUIRE_NFT")
	if os.Geteuid() != 0 {
		requireNft(t, "not running with CAP_NET_ADMIN", errors.New("euid != 0"))
	}
	b, err := NewNftBlocker(d)
	if err != nil {
		requireNft(t, "the nftables backend could not be installed", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// nftListRuleset reads the ruleset back with the nft command line, which is an
// independent reader: a mistake shared between the writer and the reader would
// otherwise cancel itself out.
func nftListRuleset(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		nftSkipf(t, "the nft command line is unavailable: %v", err)
	}
	return string(out)
}

// TestNftBlockerInstallsItsObjects checks what actually landed in the kernel.
func TestNftBlockerInstallsItsObjects(t *testing.T) {
	newLiveBlocker(t, time.Hour)

	ruleset := nftListRuleset(t)
	for _, want := range []string{
		"table inet " + nftTableName,
		"chain " + nftChainName,
		"set " + nftSetV4Name,
		"set " + nftSetV6Name,
		"type ipv4_addr",
		"type ipv6_addr",
		// Both sets carry a kernel-side timeout: the daemon's hour plus the
		// five-minute safety margin.
		"timeout 1h5m",
		// The two drop rules, one per family.
		"ip saddr @" + nftSetV4Name + " drop",
		"ip6 saddr @" + nftSetV6Name + " drop",
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("the ruleset does not contain %q:\n%s", want, ruleset)
		}
	}

	// The chain must hook input and must not become a default-deny firewall.
	// Enabling port scan detection did not ask for that.
	if !strings.Contains(ruleset, "hook input") {
		t.Errorf("the chain does not hook input:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, "policy accept") {
		t.Errorf("the chain policy is not accept:\n%s", ruleset)
	}
	if strings.Contains(ruleset, "policy drop") {
		t.Fatalf("the chain has a drop policy; that is a default-deny input firewall:\n%s", ruleset)
	}
}

// TestNftBlockerAddsAndRemovesElements covers both families through the whole
// add/observe/remove cycle.
func TestNftBlockerAddsAndRemovesElements(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)

	v4 := netip.MustParseAddr("192.0.2.66")
	v6 := netip.MustParseAddr("2001:db8::66")

	if err := b.Block(v4); err != nil {
		t.Fatalf("Block(%s): %v", v4, err)
	}
	if err := b.Block(v6); err != nil {
		t.Fatalf("Block(%s): %v", v6, err)
	}

	ruleset := nftListRuleset(t)
	if !strings.Contains(ruleset, v4.String()) {
		t.Errorf("%s is not in the ruleset:\n%s", v4, ruleset)
	}
	if !strings.Contains(ruleset, v6.String()) {
		t.Errorf("%s is not in the ruleset:\n%s", v6, ruleset)
	}

	if err := b.Unblock(v4); err != nil {
		t.Fatalf("Unblock(%s): %v", v4, err)
	}
	if err := b.Unblock(v6); err != nil {
		t.Fatalf("Unblock(%s): %v", v6, err)
	}

	ruleset = nftListRuleset(t)
	if strings.Contains(ruleset, v4.String()) || strings.Contains(ruleset, v6.String()) {
		t.Fatalf("an unblocked address is still in the ruleset:\n%s", ruleset)
	}
}

// TestNftBlockerElementCarriesAKernelTimeout is the safety net for a daemon
// that is killed rather than stopped.
//
// PortSentry has to warn in its own configuration file that its blocked list
// "will not reflect the current state of your system" after a restart, because
// nothing expires its entries. Here the kernel expires them even if the daemon
// never runs again.
func TestNftBlockerElementCarriesAKernelTimeout(t *testing.T) {
	const daemonSide = 4 * time.Hour
	b := newLiveBlocker(t, daemonSide)

	v4 := netip.MustParseAddr("192.0.2.77")
	if err := b.Block(v4); err != nil {
		t.Fatalf("Block: %v", err)
	}

	ruleset := nftListRuleset(t)

	// The set declares the timeout every element inherits: the daemon's own
	// duration plus a five-minute margin, so the daemon is normally the one
	// that expires a block and the kernel is only the fallback.
	if !strings.Contains(ruleset, "timeout 4h5m") {
		t.Fatalf("the set does not declare the daemon's %v plus the 5 minute margin:\n%s",
			daemonSide, ruleset)
	}

	// nft renders a live element as `192.0.2.77 expires 4h4m59s...`: the
	// countdown is what proves the kernel is holding it, not just the library.
	line := ""
	for _, l := range strings.Split(ruleset, "\n") {
		if strings.Contains(l, v4.String()) {
			line = strings.TrimSpace(l)
			break
		}
	}
	if line == "" {
		t.Fatalf("the element is missing from the ruleset:\n%s", ruleset)
	}
	if !strings.Contains(line, "expires") {
		t.Fatalf("the element is not counting down; it would outlive a killed daemon: %q", line)
	}
	if !strings.Contains(line, "expires 4h") {
		t.Fatalf("the element expires at %q, want a little under %v", line, daemonSide+5*time.Minute)
	}
}

// TestNftBlockerReallyDropsTraffic is the functional proof: not that a rule
// exists, but that a packet from a blocked source does not arrive.
//
// It runs entirely over loopback inside the test's own network namespace, using
// a second loopback address as the "scanner": traffic between two local
// addresses still traverses the input hook, so the rule applies.
func TestNftBlockerReallyDropsTraffic(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)

	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		nftSkipf(t, "could not bring loopback up: %v: %s", err, out)
	}
	scanner := netip.MustParseAddr("127.0.0.9")
	if out, err := exec.Command("ip", "addr", "add", scanner.String()+"/8", "dev", "lo").CombinedOutput(); err != nil &&
		!strings.Contains(string(out), "File exists") {
		nftSkipf(t, "could not add a second loopback address: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", scanner.String()+"/8", "dev", "lo").Run() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	target := ln.Addr().String()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	dialFrom := func(src netip.Addr) error {
		d := &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: net.IP(src.AsSlice())},
			Timeout:   2 * time.Second,
		}
		c, err := d.Dial("tcp", target)
		if err != nil {
			return err
		}
		return c.Close()
	}

	// Before the block, the connection must succeed -- otherwise a failure
	// afterwards would prove nothing about the rule.
	if err := dialFrom(scanner); err != nil {
		nftSkipf(t, "the baseline connection from %s failed, so this environment cannot show a drop: %v", scanner, err)
	}

	if err := b.Block(scanner); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if err := dialFrom(scanner); err == nil {
		t.Fatalf("a connection from the blocked source %s still succeeded:\n%s", scanner, nftListRuleset(t))
	}

	// A different source must still get through: the rule matches the address,
	// not the port or the interface.
	if err := dialFrom(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatalf("blocking %s also cut off 127.0.0.1: %v", scanner, err)
	}

	// And releasing must restore it.
	if err := b.Unblock(scanner); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if err := dialFrom(scanner); err != nil {
		t.Fatalf("the connection from %s did not come back after unblocking: %v", scanner, err)
	}
}

// TestNftBlockerIPv6DropsTraffic is the same proof for IPv6, which has its own
// rule, its own set and its own payload offset -- none of which the IPv4 test
// exercises.
func TestNftBlockerIPv6DropsTraffic(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)

	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		nftSkipf(t, "could not bring loopback up: %v: %s", err, out)
	}
	scanner := netip.MustParseAddr("::9")
	if out, err := exec.Command("ip", "-6", "addr", "add", scanner.String()+"/128", "dev", "lo").CombinedOutput(); err != nil &&
		!strings.Contains(string(out), "File exists") {
		nftSkipf(t, "could not add an IPv6 loopback address: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "-6", "addr", "del", scanner.String()+"/128", "dev", "lo").Run() })
	// A freshly added IPv6 address spends a moment in tentative state.
	time.Sleep(200 * time.Millisecond)

	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		nftSkipf(t, "no usable IPv6 loopback here: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	dial := func() error {
		d := &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: net.IP(scanner.AsSlice())},
			Timeout:   2 * time.Second,
		}
		c, err := d.Dial("tcp6", fmt.Sprintf("[::1]:%d", port))
		if err != nil {
			return err
		}
		return c.Close()
	}

	if err := dial(); err != nil {
		nftSkipf(t, "the IPv6 baseline connection failed: %v", err)
	}
	if err := b.Block(scanner); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if err := dial(); err == nil {
		t.Fatalf("a connection from the blocked IPv6 source still succeeded:\n%s", nftListRuleset(t))
	}
	if err := b.Unblock(scanner); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if err := dial(); err != nil {
		t.Fatalf("the IPv6 connection did not come back after unblocking: %v", err)
	}
}

// TestNftBlockerUnblockIsIdempotent: releasing a block that the kernel timeout
// already expired must not be an error. A caller cannot know which of the two
// happened first, and should not have to.
func TestNftBlockerUnblockIsIdempotent(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	v4 := netip.MustParseAddr("192.0.2.88")

	if err := b.Unblock(v4); err != nil {
		t.Fatalf("unblocking an address that was never blocked: %v", err)
	}
	if err := b.Block(v4); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if err := b.Unblock(v4); err != nil {
		t.Fatalf("first Unblock: %v", err)
	}
	if err := b.Unblock(v4); err != nil {
		t.Fatalf("second Unblock: %v", err)
	}
}

// TestNftBlockerReblockIsAccepted: the manager extends an existing block by
// calling Block again, so the backend must tolerate re-adding an element that
// is already in the set.
func TestNftBlockerReblockIsAccepted(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	v4 := netip.MustParseAddr("192.0.2.99")

	for i := 0; i < 3; i++ {
		if err := b.Block(v4); err != nil {
			t.Fatalf("Block attempt %d: %v", i+1, err)
		}
	}
	if !strings.Contains(nftListRuleset(t), v4.String()) {
		t.Fatalf("the address is not in the set after three blocks")
	}
}

// TestNftBlockerReblockRestartsTheKernelTimeout: the kernel leaves the timeout
// of an element added again as it was. A block the daemon extends must have
// its element's countdown restarted too, or the kernel ends it first.
func TestNftBlockerReblockRestartsTheKernelTimeout(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	v4 := netip.MustParseAddr("192.0.2.98")
	expires := func() time.Duration {
		t.Helper()
		for _, l := range strings.Split(nftListRuleset(t), "\n") {
			if i := strings.Index(l, v4.String()+" expires "); i >= 0 {
				f := strings.Fields(l[i+len(v4.String()+" expires "):])
				d, err := time.ParseDuration(strings.TrimRight(f[0], ",}"))
				if err != nil {
					t.Fatalf("cannot read the countdown in %q: %v", l, err)
				}
				return d
			}
		}
		t.Fatalf("the element is missing:\n%s", nftListRuleset(t))
		return 0
	}
	if err := b.Block(v4); err != nil {
		t.Fatalf("Block: %v", err)
	}
	time.Sleep(3 * time.Second)
	before := expires()
	if err := b.Block(v4); err != nil {
		t.Fatalf("Block again: %v", err)
	}
	if after := expires(); after < before+2*time.Second {
		t.Fatalf("blocking again left the kernel countdown at %v (it was %v): the kernel"+
			" would end an extended block early", after, before)
	}
}

// TestNftBlockerCloseRemovesEverything: nothing this daemon installed may
// outlive it. A rule nobody owns is a rule nobody will remove.
func TestNftBlockerCloseRemovesEverything(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)

	if err := b.Block(netip.MustParseAddr("192.0.2.66")); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if err := b.Block(netip.MustParseAddr("2001:db8::66")); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !strings.Contains(nftListRuleset(t), nftTableName) {
		t.Fatalf("the table is not installed")
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ruleset := nftListRuleset(t)
	if strings.Contains(ruleset, nftTableName) {
		t.Fatalf("the table survived Close:\n%s", ruleset)
	}
	for _, gone := range []string{"192.0.2.66", "2001:db8::66", nftChainName, nftSetV4Name} {
		if strings.Contains(ruleset, gone) {
			t.Fatalf("%q survived Close:\n%s", gone, ruleset)
		}
	}

	// Close is idempotent, and a closed blocker refuses to install more.
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := b.Block(netip.MustParseAddr("192.0.2.66")); err == nil {
		t.Fatalf("a closed blocker accepted a block")
	}
	if err := b.Unblock(netip.MustParseAddr("192.0.2.66")); err != nil {
		t.Fatalf("a closed blocker must ignore Unblock, got %v", err)
	}
}

func TestNftBlockerRefusesAnInvalidDuration(t *testing.T) {
	if _, err := NewNftBlocker(0); err == nil {
		t.Fatalf("a zero block duration must be refused")
	}
	if _, err := NewNftBlocker(-time.Second); err == nil {
		t.Fatalf("a negative block duration must be refused")
	}
}

// TestNftBlockerThroughTheBlockManager runs the real backend under the policy
// layer that owns it, which is how the daemon uses it: expiry, the cap on
// simultaneous blocks, and release on shutdown, all against the real kernel.
func TestNftBlockerThroughTheBlockManager(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)

	cfg := testBlockConfig()
	cfg.MaxBlockedSources = 2
	cfg.Duration = time.Hour
	mgr, now := newTestBlockManager(t, b, cfg, func(netip.Addr) bool { return false })

	a1 := netip.MustParseAddr("192.0.2.11")
	a2 := netip.MustParseAddr("192.0.2.12")
	a3 := netip.MustParseAddr("192.0.2.13")

	for _, a := range []netip.Addr{a1, a2, a3} {
		if err := mgr.Block(a, "test"); err != nil {
			t.Fatalf("Block(%s): %v", a, err)
		}
	}

	// The cap evicted the oldest, and the eviction reached the kernel.
	ruleset := nftListRuleset(t)
	if strings.Contains(ruleset, a1.String()) {
		t.Fatalf("the evicted address %s is still in the kernel set:\n%s", a1, ruleset)
	}
	for _, a := range []netip.Addr{a2, a3} {
		if !strings.Contains(ruleset, a.String()) {
			t.Fatalf("%s should be blocked:\n%s", a, ruleset)
		}
	}

	// Expiry reaches the kernel too.
	*now = now.Add(2 * time.Hour)
	if n := mgr.ExpireDue(); n != 2 {
		t.Fatalf("ExpireDue removed %d entries, want 2", n)
	}
	ruleset = nftListRuleset(t)
	for _, a := range []netip.Addr{a2, a3} {
		if strings.Contains(ruleset, a.String()) {
			t.Fatalf("the expired address %s is still in the kernel set:\n%s", a, ruleset)
		}
	}

	// And shutdown leaves nothing behind.
	if err := mgr.Block(a1, "test"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	mgr.Stop()
	if strings.Contains(nftListRuleset(t), a1.String()) {
		t.Fatalf("a block survived BlockManager.Stop")
	}
}

// TestNftBlockerRecoversFromAFlushedRuleset guards against a silent loss of
// protection.
//
// `nft flush ruleset` is the first line of almost every /etc/nftables.conf, so
// any `systemctl restart nftables` takes the table away. If nothing put it
// back, ready would stay true, every later Block would fail identically, and
// the host would be unprotected until the daemon was restarted -- with nothing
// saying so.
func TestNftBlockerRecoversFromAFlushedRuleset(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)

	v4 := netip.MustParseAddr("192.0.2.66")
	if err := b.Block(v4); err != nil {
		t.Fatalf("Block: %v", err)
	}

	if out, err := exec.Command("nft", "flush", "ruleset").CombinedOutput(); err != nil {
		nftSkipf(t, "could not flush the ruleset: %v: %s", err, out)
	}
	if strings.Contains(nftListRuleset(t), nftTableName) {
		t.Fatalf("the flush did not remove the table")
	}

	other := netip.MustParseAddr("192.0.2.77")
	if err := b.Block(other); err != nil {
		t.Fatalf("Block after the ruleset was flushed: %v", err)
	}

	ruleset := nftListRuleset(t)
	if !strings.Contains(ruleset, nftTableName) {
		t.Fatalf("the table was not rebuilt:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, other.String()) {
		t.Fatalf("%s is not in the rebuilt set:\n%s", other, ruleset)
	}
	if !strings.Contains(ruleset, "ip saddr @"+nftSetV4Name+" drop") {
		t.Fatalf("the rebuilt table has no drop rule:\n%s", ruleset)
	}
}

// TestNftBlockerRebuildRestoresEveryBlock: after the ruleset is flushed under
// it, the rebuild must reinstall everything it claims to be blocking.
//
// A rebuild that reinstalled only the address that happened to be in flight
// would lie. Measured with such a rebuild: three blocks installed, `nft delete
// table`, a fourth block -- kernel holds one element, the manager lists four,
// and Monitor.Blocked(), the status output and the user interface all report
// four active blocks. Worse than a cosmetic lie: IsBlocked() would answer true
// for the three that are no longer filtered, so handleEvent would class a
// fresh scan from them as already handled and the user would never be told.
// `nft flush ruleset` is the first line of nearly every /etc/nftables.conf, so
// any `systemctl restart nftables` reaches this.
func TestNftBlockerRebuildRestoresEveryBlock(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)

	installed := []netip.Addr{
		netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("198.51.100.2"),
		netip.MustParseAddr("2001:db8::1"),
	}
	for _, a := range installed {
		if err := b.Block(a); err != nil {
			t.Fatalf("Block(%s): %v", a, err)
		}
	}
	// Forty minutes pass before the flush. A restored element must get the time
	// its block has LEFT: a full timeout would keep it in the kernel forty
	// minutes too long if the daemon died after the rebuild.
	b.now = func() time.Time { return time.Now().Add(40 * time.Minute) }

	if out, err := exec.Command("nft", "flush", "ruleset").CombinedOutput(); err != nil {
		nftSkipf(t, "could not flush the ruleset: %v: %s", err, out)
	}

	trigger := netip.MustParseAddr("198.51.100.4")
	if err := b.Block(trigger); err != nil {
		t.Fatalf("Block after the ruleset was flushed: %v", err)
	}

	ruleset := nftListRuleset(t)
	for _, a := range append(installed, trigger) {
		if !strings.Contains(ruleset, a.String()) {
			t.Errorf("%s is not in the rebuilt sets; the daemon reports it as blocked"+
				" and the kernel is not dropping it:\n%s", a, ruleset)
		}
	}
	full := time.Hour + 5*time.Minute
	for _, a := range installed {
		if left := nftElementTimeLeft(t, a); left > full-39*time.Minute {
			t.Errorf("%s was restored with %v in the kernel, 40 minutes into a %v"+
				" timeout: it was given the full timeout again", a, left.Round(time.Second), full)
		}
	}
}

// TestNftBlockerCloseRemovesTheTableEvenWhenNotReady: a Close that returned
// nil without looking whenever ready was false would leave the table and its
// input hook behind. A failed setup can install the table and then fail on a
// later object, and a rebuild can leave !ready with the table fully present --
// so every stop/start that landed there would leave another two rules in the
// path of every inbound packet on the machine.
func TestNftBlockerCloseRemovesTheTableEvenWhenNotReady(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	if err := b.Block(netip.MustParseAddr("198.51.100.9")); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !strings.Contains(nftListRuleset(t), nftTableName) {
		t.Fatal("the table was not installed")
	}

	// The state a Close that trusts ready would treat as "nothing to do".
	b.mu.Lock()
	b.ready = false
	b.mu.Unlock()

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if ruleset := nftListRuleset(t); strings.Contains(ruleset, nftTableName) {
		t.Fatalf("the table survived Close:\n%s", ruleset)
	}
}

// TestNftBlockerRefusesToTakeOverALiveInstancesTable: setup deletes any
// homonymous table, which, done blindly, would silently take a running
// daemon's protection away while it went on reporting the source as blocked.
// The rules carry an owner token; a token naming a live process is a refusal,
// a token naming a dead one is not.
func TestNftBlockerRefusesToTakeOverALiveInstancesTable(t *testing.T) {
	// Decided before any subtest runs: a skip raised from inside one of them
	// would be a FailNow on the parent, which the testing package reports as a
	// panic rather than as the skip it is.
	requireDisposableNetwork(t, "PORTSCAN_REQUIRE_NFT")
	if os.Geteuid() != 0 {
		requireNft(t, "not running with CAP_NET_ADMIN", errors.New("euid != 0"))
	}

	// PID 1 is alive on any running system, and its start time makes the token
	// name that process specifically rather than whatever reuses the number.
	start, err := procStartTime(1)
	if err != nil {
		nftSkipf(t, "cannot read /proc/1/stat: %v", err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		nftSkipf(t, "cannot read the boot id: %v", err)
	}
	liveToken := fmt.Sprintf("owner boot=%s pid=1 start=%s", strings.TrimSpace(string(boot)), start)
	if !ownerIsAlive(liveToken) {
		t.Fatalf("ownerIsAlive(%q) = false for PID 1, which is running", liveToken)
	}

	install := func(t *testing.T, token string) *NftBlocker {
		t.Helper()
		conn, err := nftables.New()
		if err != nil {
			requireNft(t, "opening a netlink connection", err)
		}
		first := &NftBlocker{
			conn:    conn,
			timeout: time.Hour,
			live:    map[netip.Addr]time.Time{},
			owner:   token,
			now:     time.Now,
		}
		if err := first.setup(); err != nil {
			requireNft(t, "the nftables backend could not be installed", err)
		}
		return first
	}

	t.Run("live owner is refused", func(t *testing.T) {
		first := install(t, liveToken)
		defer func() { _ = first.Close() }()
		if err := first.Block(netip.MustParseAddr("198.51.100.5")); err != nil {
			t.Fatalf("Block: %v", err)
		}

		second, err := NewNftBlocker(time.Hour)
		if err == nil {
			_ = second.Close()
			t.Fatal("a second blocker took over a live instance's table; the first goes on" +
				" reporting its sources as blocked while nothing drops them")
		}
		if !errors.Is(err, ErrTableOwnedByLiveInstance) {
			t.Fatalf("err = %v, want ErrTableOwnedByLiveInstance", err)
		}
		if !strings.Contains(nftListRuleset(t), "198.51.100.5") {
			t.Fatal("the refusal did not leave the first instance's block in place")
		}
	})

	t.Run("dead owner is taken over", func(t *testing.T) {
		// Same boot, PID 1, but a start time that cannot be PID 1's: the token
		// names a process that no longer exists.
		deadToken := fmt.Sprintf("owner boot=%s pid=1 start=%s0", strings.TrimSpace(string(boot)), start)
		if ownerIsAlive(deadToken) {
			t.Fatalf("ownerIsAlive(%q) = true; the token was meant to name a dead process", deadToken)
		}
		first := install(t, deadToken)
		_ = first
		second, err := NewNftBlocker(time.Hour)
		if err != nil {
			t.Fatalf("a table left by a dead instance must be adopted, got: %v", err)
		}
		_ = second.Close()
	})

	// A daemon that does not block builds no blocker, so nothing above runs
	// for it: RemoveLeftoverTable is what clears a dead instance's blocks.
	t.Run("without a blocker, a dead owner's table is removed", func(t *testing.T) {
		deadToken := fmt.Sprintf("owner boot=%s pid=1 start=%s0", strings.TrimSpace(string(boot)), start)
		first := install(t, deadToken)
		if err := first.Block(netip.MustParseAddr("198.51.100.6")); err != nil {
			t.Fatalf("Block: %v", err)
		}
		removed, err := RemoveLeftoverTable()
		if err != nil || !removed {
			t.Fatalf("RemoveLeftoverTable = %v, %v; want true, nil", removed, err)
		}
		if strings.Contains(nftListRuleset(t), nftTableName) {
			t.Fatal("the table of a dead instance is still installed, its block with it")
		}
		removed, err = RemoveLeftoverTable()
		if err != nil || removed {
			t.Fatalf("with no table, RemoveLeftoverTable = %v, %v; want false, nil", removed, err)
		}
	})

	t.Run("without a blocker, a live owner's table is left alone", func(t *testing.T) {
		first := install(t, liveToken)
		defer func() { _ = first.Close() }()
		if err := first.Block(netip.MustParseAddr("198.51.100.7")); err != nil {
			t.Fatalf("Block: %v", err)
		}
		removed, err := RemoveLeftoverTable()
		if err != nil || removed {
			t.Fatalf("RemoveLeftoverTable = %v, %v; want false, nil", removed, err)
		}
		if !strings.Contains(nftListRuleset(t), "198.51.100.7") {
			t.Fatal("the table of a running instance was removed")
		}
	})
}

// TestNftBlockerRestartDoesNotAccumulateRules: setup appends its rules, so if
// the table survived a shutdown, each start would leave two more in the input
// hook -- sixteen after eight restarts, each a comparison every inbound packet
// on the machine has to make.
func TestNftBlockerRestartDoesNotAccumulateRules(t *testing.T) {
	requireDisposableNetwork(t, "PORTSCAN_REQUIRE_NFT")
	countRules := func() int {
		n := 0
		for _, line := range strings.Split(nftListRuleset(t), "\n") {
			if strings.Contains(line, "saddr @portscan_sources_") {
				n++
			}
		}
		return n
	}

	for round := 1; round <= 4; round++ {
		b, err := NewNftBlocker(time.Hour)
		if err != nil {
			requireNft(t, "the nftables backend could not be installed", err)
		}
		if got := countRules(); got != 2 {
			t.Fatalf("after start %d: %d drop rules in the input hook, want 2", round, got)
		}
		// Deliberately NOT closed on every round: the point is that a table
		// left behind by a previous instance is not adopted and appended to.
		if round == 4 {
			_ = b.Close()
		}
	}
	if got := countRules(); got != 0 {
		t.Fatalf("%d rules survived Close", got)
	}
}

// TestUnblockManyIsOneTransaction pins that releasing a batch of blocks costs
// one netlink round trip rather than one per address, against the real kernel.
//
// It is a performance property, but the reason it is asserted here is a
// correctness one: releasing one at a time would hold BlockManager.mu for the
// whole pass, and every nftables commit is serialised per network namespace,
// so the cost would not be confined to this feature. Measured one at a time:
// 128 releases took 795 ms, during which an unrelated transaction -- including
// OpenSnitch's own rule checks -- slowed roughly eightfold. Batched, the same
// 128 took 8.3 ms.
//
// The ratio is asserted loosely because it depends on the machine, but
// per-address round trips would lose two orders of magnitude, not a few
// percent.
func TestUnblockManyIsOneTransaction(t *testing.T) {
	const n = 128
	addrs := make([]netip.Addr, n)
	for i := range addrs {
		addrs[i] = netip.AddrFrom4([4]byte{198, 51, byte(i / 256), byte(i % 256)})
	}

	oneByOne := func() time.Duration {
		b := newLiveBlocker(t, time.Hour)
		defer b.Close()
		for _, a := range addrs {
			if err := b.Block(a); err != nil {
				t.Fatalf("Block(%s): %v", a, err)
			}
		}
		start := time.Now()
		for _, a := range addrs {
			_ = b.Unblock(a)
		}
		return time.Since(start)
	}()

	batched := func() time.Duration {
		b := newLiveBlocker(t, time.Hour)
		defer b.Close()
		for _, a := range addrs {
			if err := b.Block(a); err != nil {
				t.Fatalf("Block(%s): %v", a, err)
			}
		}
		start := time.Now()
		if err := b.UnblockMany(addrs); err != nil {
			t.Fatalf("UnblockMany: %v", err)
		}
		elapsed := time.Since(start)

		// It really released them: the kernel must not still be dropping any
		// of them. Read back through the nft command line, so what is checked
		// is what the kernel holds rather than what the library believes it
		// sent.
		if rs := nftListRuleset(t); strings.Contains(rs, addrs[0].String()) ||
			strings.Contains(rs, addrs[n/2].String()) ||
			strings.Contains(rs, addrs[n-1].String()) {
			t.Fatal("addresses are still in the kernel set after UnblockMany")
		}
		return elapsed
	}()

	t.Logf("releasing %d blocks: one at a time %v, batched %v (%.0fx)",
		n, oneByOne, batched, float64(oneByOne)/float64(batched))

	if batched >= oneByOne/4 {
		t.Fatalf("batched release took %v against %v one at a time: the batch is"+
			" not reaching the kernel as a single transaction", batched, oneByOne)
	}
}

// TestUnblockManyReleasesMoreThanOneMessageHolds: a set's element list is one
// netlink attribute with a 16-bit length, truncated without an error past
// 4095 IPv4 or 2340 IPv6 deletions: the kernel released none or part of them,
// mostly answering success; past about 12 000 the message itself failed and
// the caller fell back to one transaction per address, minutes with
// detection stopped. Each family is also tried
// alone, where a batch is all of one family. The sets are filled through the
// nft command line, which takes them all in one go.
func TestUnblockManyReleasesMoreThanOneMessageHolds(t *testing.T) {
	for _, n := range [][2]int{{20000, 5000}, {0, 5000}, {6000, 0}} {
		t.Run(fmt.Sprintf("v4=%d,v6=%d", n[0], n[1]), func(t *testing.T) {
			unblockManyReleases(t, n[0], n[1])
		})
	}
}

func unblockManyReleases(t *testing.T, n4, n6 int) {
	b := newLiveBlocker(t, time.Hour)
	var addrs []netip.Addr
	fill := func(set string, elems []string) {
		if len(elems) == 0 {
			return
		}
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(fmt.Sprintf("add element inet %s %s { %s }\n",
			nftTableName, set, strings.Join(elems, ", ")))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("filling %s: %v: %s", set, err, out)
		}
	}
	var v4, v6 []string
	for i := 0; i < n4; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		addrs, v4 = append(addrs, a), append(v4, a.String())
	}
	for i := 0; i < n6; i++ {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)})
		addrs, v6 = append(addrs, a), append(v6, a.String())
	}
	fill(nftSetV4Name, v4)
	fill(nftSetV6Name, v6)
	start := time.Now()
	if err := b.UnblockMany(addrs); err != nil {
		t.Fatalf("UnblockMany(%d): %v", len(addrs), err)
	}
	t.Logf("released %d blocks in %v", len(addrs), time.Since(start))
	assertSetSizes(t, map[string]int{nftSetV4Name: 0, nftSetV6Name: 0})
}

// assertSetSizes counts the elements the kernel holds in each set.
func assertSetSizes(t *testing.T, want map[string]int) {
	t.Helper()
	for set, n := range want {
		out, err := exec.Command("nft", "list", "set", "inet", nftTableName, set).CombinedOutput()
		if err != nil {
			t.Fatalf("nft list set %s: %v: %s", set, err, out)
		}
		if got := strings.Count(string(out), " expires "); got != n {
			t.Errorf("%s holds %d elements, want %d", set, got, n)
		}
	}
}

// TestUnblockManyReleasesTheRestWhenOneIsGone: one element already gone from
// the kernel fails a whole batched deletion with ENOENT. Read as "already
// gone" for all of them, it would leave the others blocked, unsaid, until the
// kernel timeout.
func TestUnblockManyReleasesTheRestWhenOneIsGone(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	var addrs []netip.Addr
	for i := 1; i <= 10; i++ {
		a := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
		if err := b.Block(a); err != nil {
			t.Fatalf("Block(%s): %v", a, err)
		}
		addrs = append(addrs, a)
	}
	if out, err := exec.Command("nft", "delete", "element", "inet", nftTableName,
		nftSetV4Name, "{ 198.51.100.5 }").CombinedOutput(); err != nil {
		t.Fatalf("nft delete element: %v: %s", err, out)
	}
	if err := b.UnblockMany(addrs); err != nil {
		t.Fatalf("UnblockMany: %v", err)
	}
	assertSetSizes(t, map[string]int{nftSetV4Name: 0})
}

// TestRepairRestoresManyBlocks: a rebuild after `nft flush ruleset` that
// queued one message per element would, from a few hundred blocks, never see
// the commit return, with the blocker's lock held, and from a few thousand it
// would fail and the table would never be rebuilt.
func TestRepairRestoresManyBlocks(t *testing.T) {
	// Both ways it can fail: 500 hung, 23 000 did not fit in one send. Each
	// family alone too: a list of more than 2340 IPv4 or 1638 IPv6 elements
	// with a timeout is truncated without an error.
	for _, n := range [][2]int{{400, 100}, {20000, 3000}, {0, 5000}, {6000, 0}} {
		t.Run(fmt.Sprintf("v4=%d,v6=%d", n[0], n[1]), func(t *testing.T) {
			repairRestores(t, n[0], n[1])
		})
	}
}

func repairRestores(t *testing.T, n4, n6 int) {
	b := newLiveBlocker(t, time.Hour)
	deadline := time.Now().Add(time.Hour)
	b.mu.Lock()
	for i := 0; i < n4; i++ {
		b.live[netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})] = deadline
	}
	for i := 0; i < n6; i++ {
		b.live[netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)})] = deadline
	}
	b.mu.Unlock()
	if out, err := exec.Command("nft", "flush", "ruleset").CombinedOutput(); err != nil {
		t.Fatalf("nft flush ruleset: %v: %s", err, out)
	}
	done := make(chan error, 1)
	go func() {
		repaired, err := b.Repair()
		if err == nil && !repaired {
			err = errors.New("Repair did not rebuild a table that is gone")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Repair: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Repair did not return within 30 s")
	}
	assertSetSizes(t, map[string]int{nftSetV4Name: n4, nftSetV6Name: n6})
}

// TestExpiryPassIsOneTransaction pins the batching at the level the daemon
// actually runs it: BlockManager.ExpireDue and BlockManager.Stop, not the
// blocker in isolation.
//
// Measured only through NftBlocker.UnblockMany, the batch looks like a
// hundredfold win, and it would be worth nothing if releaseManyLocked emptied
// the kernel's set but left the manager's own map untouched: the per-address
// pass that followed would still find every entry and still call Unblock -- a
// SetDeleteElements plus a Flush each. "Already gone" would be true of the
// kernel and false of the map, and the cost is the Flush. Measured that way
// against a real kernel, ExpireDue over 128 addresses took 804.9 ms: the
// 803.2 ms it takes without any batch, plus the batch -- one transaction
// added instead of 127 removed.
//
// Hence the assertion below: it measures the path, not the component.
func TestExpiryPassIsOneTransaction(t *testing.T) {
	const n = 128

	build := func() (*BlockManager, *NftBlocker) {
		b := newLiveBlocker(t, time.Hour)
		m, err := NewBlockManager(b, BlockConfig{Duration: time.Hour, MaxBlockedSources: n + 8},
			func(netip.Addr) bool { return false })
		if err != nil {
			t.Fatalf("NewBlockManager: %v", err)
		}
		m.SetOnError(func(error) {})
		for i := 0; i < n; i++ {
			a := netip.AddrFrom4([4]byte{198, 51, byte(i / 256), byte(i % 256)})
			if err := m.Block(a, "scan"); err != nil {
				t.Fatalf("Block(%s): %v", a, err)
			}
		}
		return m, b
	}

	// Everything due at once, which is what a decoy scan produces: the blocks
	// all went in together, so they all come out together.
	m, b := build()
	m.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	start := time.Now()
	released := m.ExpireDue()
	expire := time.Since(start)
	if released != n {
		t.Errorf("ExpireDue released %d of %d", released, n)
	}
	if rs := nftListRuleset(t); strings.Contains(rs, "198.51.0.0") {
		t.Error("an expired address is still in the kernel set")
	}
	_ = b.Close()

	m2, b2 := build()
	start = time.Now()
	m2.Stop()
	stop := time.Since(start)
	_ = b2.Close()

	t.Logf("over %d addresses: ExpireDue %v, Stop %v", n, expire, stop)

	// Per-address round trips cost roughly 6 ms each against a real kernel, so
	// 128 of them is the better part of a second. A limit of 150 ms is far above
	// one batch (about 10 ms) and far below the un-batched behaviour, and it
	// leaves room for a slow machine.
	const limit = 150 * time.Millisecond
	if expire > limit {
		t.Errorf("ExpireDue took %v for %d addresses: the expiry pass is issuing"+
			" one transaction per address again", expire, n)
	}
	if stop > limit {
		t.Errorf("Stop took %v for %d addresses: shutdown -- which a configuration"+
			" reload runs -- is issuing one transaction per address again", stop, n)
	}
}

// TestBlocksSurviveAReadopt pins that blocks in force are carried across a
// configuration reload, with the time they had left.
//
// The reload tears detection down and builds it again, and the teardown releases
// every block -- right at shutdown, wrong there. Measured against a real kernel
// without the carry-over: a scan had installed a four-hour block, the operator
// changed an unrelated setting, and the nftables set came back empty.
func TestBlocksSurviveAReadopt(t *testing.T) {
	build := func() (*BlockManager, *NftBlocker) {
		b := newLiveBlocker(t, 4*time.Hour)
		m, err := NewBlockManager(b, BlockConfig{Duration: 4 * time.Hour, MaxBlockedSources: 16},
			func(netip.Addr) bool { return false })
		if err != nil {
			t.Fatalf("NewBlockManager: %v", err)
		}
		m.SetOnError(func(error) {})
		return m, b
	}

	scanner := netip.MustParseAddr("198.51.100.77")

	// A block is installed, then everything is torn down as a reload does.
	m1, b1 := build()
	if err := m1.Block(scanner, "TCP SYN scan"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	held := m1.Blocked()
	if len(held) != 1 {
		t.Fatalf("held %d blocks before the reload, want 1", len(held))
	}
	m1.Stop()
	_ = b1.Close()

	// The new instance adopts what the old one held.
	m2, b2 := build()
	defer func() { m2.Stop(); b2.Close() }()
	m2.Readopt(held)

	after := m2.Blocked()
	if len(after) != 1 || after[0].Addr != scanner {
		t.Fatalf("after the reload the manager holds %v, want a block for %s",
			after, scanner)
	}
	if rs := nftListRuleset(t); !strings.Contains(rs, scanner.String()) {
		t.Fatal("the address is listed by the manager but is not in the kernel set")
	}

	// The remaining time is carried, not restarted: a reload must not be a way
	// to extend a block either.
	left := time.Until(after[0].ExpiresAt)
	if left > 4*time.Hour {
		t.Fatalf("the adopted block has %v left, more than a full duration", left)
	}

	// A reload that shortens the duration shortens the blocks it carries. The
	// kernel element gets the new backend's timeout; an expiry left at four
	// hours claimed a block the kernel had released minutes after the reload.
	short := func() (*BlockManager, *NftBlocker) {
		b := newLiveBlocker(t, time.Minute)
		m, err := NewBlockManager(b, BlockConfig{Duration: time.Minute, MaxBlockedSources: 16},
			func(netip.Addr) bool { return false })
		if err != nil {
			t.Fatalf("NewBlockManager: %v", err)
		}
		m.SetOnError(func(error) {})
		return m, b
	}
	m4, b4 := short()
	m4.Readopt(held)
	adopted := m4.Blocked()
	if len(adopted) != 1 {
		t.Fatalf("after a reload to a one-minute duration the manager holds %v", adopted)
	}
	kernelLeft := nftElementTimeLeft(t, scanner)
	if memLeft := time.Until(adopted[0].ExpiresAt); memLeft > kernelLeft {
		t.Fatalf("after shortening the duration the manager holds the block for %v"+
			" more, but the kernel drops it in %v", memLeft.Round(time.Second), kernelLeft)
	}
	m4.Stop()
	_ = b4.Close()

	// An address that has since become exempt is NOT re-installed: a reload is
	// exactly when an operator adds the address that cut them off.
	m3, b3 := build()
	defer func() { m3.Stop(); b3.Close() }()
	m3.isExempt = func(a netip.Addr) bool { return a == scanner }
	m3.Readopt(held)
	if n := len(m3.Blocked()); n != 0 {
		t.Fatalf("an address added to the never-block list was re-adopted anyway (%d held)", n)
	}
}

// nftElementTimeLeft reads, from `nft list ruleset`, how long the kernel still
// holds addr: the `expires` countdown of its set element.
func nftElementTimeLeft(t *testing.T, addr netip.Addr) time.Duration {
	t.Helper()
	for _, l := range strings.Split(nftListRuleset(t), "\n") {
		if !strings.Contains(l, addr.String()) {
			continue
		}
		f := strings.Fields(l[strings.Index(l, addr.String()):])
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "expires" {
				d, err := time.ParseDuration(strings.TrimRight(f[i+1], ",}"))
				if err != nil {
					t.Fatalf("cannot read the countdown %q: %v", f[i+1], err)
				}
				return d
			}
		}
		t.Fatalf("the element for %s has no countdown: %q", addr, l)
	}
	t.Fatalf("no element for %s in the ruleset", addr)
	return 0
}

// TestARemovedTableIsRebuiltByTheExpiryPass: if after `nft flush ruleset` the
// table were rebuilt only when a new address was blocked, a scanner listed as
// blocked would until then be free to come back, and would be reported
// "blocked" when it did. The expiry pass, every thirty seconds, puts it back
// -- after the whole ruleset is flushed, and after only this table's rules
// are.
func TestARemovedTableIsRebuiltByTheExpiryPass(t *testing.T) {
	for _, flush := range [][]string{
		{"flush", "ruleset"},
		{"flush", "table", "inet", nftTableName},
	} {
		b := newLiveBlocker(t, time.Hour)
		m, err := NewBlockManager(b, BlockConfig{Duration: time.Hour, MaxBlockedSources: 16},
			func(netip.Addr) bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		var reported []error
		m.SetOnError(func(err error) { reported = append(reported, err) })
		a := netip.MustParseAddr("198.51.100.7")
		if err := m.Block(a, "test"); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("nft", flush...).CombinedOutput(); err != nil {
			nftSkipf(t, "nft %v: %v: %s", flush, err, out)
		}
		m.ExpireDue()
		ruleset := nftListRuleset(t)
		if !strings.Contains(ruleset, a.String()) || strings.Count(ruleset, " drop") != 2 {
			t.Errorf("after nft %v and one expiry pass the kernel does not drop %s,"+
				" which the daemon lists as blocked:\n%s", flush, a, ruleset)
		}
		if len(reported) != 0 {
			t.Errorf("the rebuild reported %v", reported)
		}
		// An intact table is left alone: no second pair of rules.
		m.ExpireDue()
		if n := strings.Count(nftListRuleset(t), " drop"); n != 2 {
			t.Errorf("an expiry pass over an intact table left %d drop rules, want 2", n)
		}
		m.Stop()
		b.Close()
	}
}

// nftTableHandle is the kernel's handle for the blocker's table: a rebuild
// gives the table a new one.
func nftTableHandle(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "-a", "list", "table", "inet", nftTableName).CombinedOutput()
	if err != nil {
		return ""
	}
	first := strings.SplitN(string(out), "\n", 2)[0]
	if i := strings.Index(first, "# handle "); i >= 0 {
		return strings.TrimSpace(first[i+len("# handle "):])
	}
	return ""
}

// TestRepairLeavesAnIntactTableAlone: a rebuild deletes the table and
// installs it again, so rebuilding an intact one every thirty seconds would
// lift every block for the moment in between.
func TestRepairLeavesAnIntactTableAlone(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	if err := b.Block(netip.MustParseAddr("198.51.100.7")); err != nil {
		t.Fatal(err)
	}
	before := nftTableHandle(t)
	if repaired, err := b.Repair(); repaired || err != nil {
		t.Fatalf("Repair on an intact table: repaired=%v err=%v", repaired, err)
	}
	if after := nftTableHandle(t); after != before || after == "" {
		t.Fatalf("the table's handle went from %q to %q: it was rebuilt", before, after)
	}
}

// TestRepairAfterCloseInstallsNothing: an expiry pass can be waiting for the
// manager's lock while the daemon stops and closes the blocker. Repair then
// runs on a closed blocker and must not put the table back behind it.
func TestRepairAfterCloseInstallsNothing(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if repaired, err := b.Repair(); repaired || err != nil {
		t.Fatalf("Repair after Close: repaired=%v err=%v", repaired, err)
	}
	if strings.Contains(nftListRuleset(t), nftTableName) {
		t.Fatal("Repair after Close installed the table again")
	}
}

// TestRepairRestoresPartialDamage: a table that is still there with one of
// its drop rules deleted, or without its chain, is not intact either.
func TestRepairRestoresPartialDamage(t *testing.T) {
	a := netip.MustParseAddr("198.51.100.7")
	for _, damage := range []func(t *testing.T){
		func(t *testing.T) {
			out, _ := exec.Command("nft", "-a", "list", "chain", "inet", nftTableName, nftChainName).CombinedOutput()
			for _, line := range strings.Split(string(out), "\n") {
				if i := strings.Index(line, "drop # handle "); i >= 0 {
					h := strings.TrimSpace(line[i+len("drop # handle "):])
					if out, err := exec.Command("nft", "delete", "rule", "inet", nftTableName, nftChainName, "handle", h).CombinedOutput(); err != nil {
						t.Fatalf("deleting a rule: %v: %s", err, out)
					}
					return
				}
			}
			t.Fatalf("no drop rule found:\n%s", out)
		},
		func(t *testing.T) {
			for _, args := range [][]string{
				{"flush", "chain", "inet", nftTableName, nftChainName},
				{"delete", "chain", "inet", nftTableName, nftChainName},
			} {
				if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
					t.Fatalf("nft %v: %v: %s", args, err, out)
				}
			}
		},
	} {
		b := newLiveBlocker(t, time.Hour)
		if err := b.Block(a); err != nil {
			t.Fatal(err)
		}
		damage(t)
		if repaired, err := b.Repair(); !repaired || err != nil {
			t.Fatalf("Repair after partial damage: repaired=%v err=%v", repaired, err)
		}
		ruleset := nftListRuleset(t)
		if strings.Count(ruleset, " drop") != 2 || !strings.Contains(ruleset, a.String()) {
			t.Fatalf("after Repair the table is not whole:\n%s", ruleset)
		}
		b.Close()
	}
}

// nftSkipf skips when the environment cannot run a live nftables test, and
// fails instead under PORTSCAN_REQUIRE_NFT=1: CI sets it so that a runner
// missing a piece -- the nft command, a loopback address -- cannot pass with
// the test unrun.
func nftSkipf(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("PORTSCAN_REQUIRE_NFT") == "1" {
		t.Fatalf("PORTSCAN_REQUIRE_NFT=1 but "+format, args...)
	}
	t.Skipf(format, args...)
}
