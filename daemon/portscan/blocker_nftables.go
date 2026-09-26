//go:build linux

package portscan

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Names of the objects this blocker owns. They are namespaced so that nothing
// here can collide with, or be mistaken for, the rules OpenSnitch installs for
// connection interception.
const (
	nftTableName   = "opensnitch-portscan"
	nftChainName   = "portscan-input"
	nftSetV4Name   = "portscan_sources_v4"
	nftSetV6Name   = "portscan_sources_v6"
	nftRuleComment = "opensnitch: port scan source"
)

// NftBlocker drops inbound traffic from scanning sources with nftables: a set
// plus two static rules, not a rule per address.
//
//   - blocking is a set element operation, so the rule list never churns (a
//     rule per attacker is a hundred rules under a decoy scan);
//   - the set carries a kernel-side timeout slightly longer than the daemon's
//     block duration, so a killed daemon's blocks still expire;
//   - everything lives in its own table, removed in one operation.
//
// Blocking happens in nftables rather than inside the eBPF program so the user
// can see, audit and undo what their firewall is doing.
type NftBlocker struct {
	mu sync.Mutex
	// describeMu serialises Describe, which reads on a connection of its own
	// and so does not take mu.
	describeMu sync.Mutex
	conn       *nftables.Conn
	table      *nftables.Table
	chain      *nftables.Chain
	setV4      *nftables.Set
	setV6      *nftables.Set
	timeout    time.Duration
	ready      bool
	closed     bool

	// live is what this blocker believes the kernel is dropping, with each
	// element's deadline, so the table can be rebuilt with its blocks when it
	// vanishes: `nft flush ruleset` opens nearly every /etc/nftables.conf, and the
	// daemon and the user interface must not go on listing blocks the kernel no
	// longer applies. Bounded by the manager's cap and pruned by deadline on every
	// rebuild.
	live map[netip.Addr]time.Time

	// owner is the token written into the drop rules' UserData, identifying the
	// process that installed them. See tableOwnerIsAlive.
	owner string

	// now is the clock, replaceable in tests.
	now func() time.Time
}

// ErrTableOwnedByLiveInstance is returned when the table already exists and
// belongs to a process still running: taking it over would delete that
// instance's blocks while it goes on reporting them.
var ErrTableOwnedByLiveInstance = errors.New("portscan: the nftables table is owned by a running instance")

// NewNftBlocker prepares the table, chain, sets and rules. The kernel-side
// timeout is longer than blockDuration, so the daemon, which can tell the user,
// normally expires a block, and the kernel is the safety net.
func NewNftBlocker(blockDuration time.Duration) (*NftBlocker, error) {
	if blockDuration <= 0 {
		return nil, fmt.Errorf("portscan: block duration must be greater than 0")
	}
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("portscan: opening a netlink connection to nftables: %w", err)
	}
	b := &NftBlocker{
		conn:    conn,
		timeout: blockDuration + 5*time.Minute,
		live:    map[netip.Addr]time.Time{},
		owner:   ownerToken(),
		now:     time.Now,
	}
	if err := b.setup(); err != nil {
		return nil, err
	}
	return b, nil
}

// RemoveLeftoverTable deletes the table of an instance that is no longer
// running, for a daemon that builds no NftBlocker (detection off, or the
// policy "never"). Only a blocker's setup deletes such a table otherwise, so
// a daemon killed with blocks in force, then restarted without blocking,
// would leave them dropping traffic until the kernel timeout, listed nowhere,
// and its table and rules for good. A table whose owner is alive, or cannot
// be read, is left alone. It reports whether a table was deleted.
//
// The owner is read, then the table deleted by name, in two transactions:
// the netlink library offers no deletion by handle. A blocking daemon that sets up
// its table in between loses it, and its Repair puts it back.
func RemoveLeftoverTable() (bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return false, fmt.Errorf("portscan: opening a netlink connection to nftables: %w", err)
	}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, fmt.Errorf("portscan: listing the nftables tables: %w", err)
	}
	b := &NftBlocker{conn: conn}
	for _, t := range tables {
		if t.Name != nftTableName {
			continue
		}
		owner, ok := b.tableOwner(t)
		if !ok || ownerIsAlive(owner) {
			return false, nil
		}
		conn.DelTable(t)
		if err := conn.Flush(); err != nil {
			if isNotExist(err) {
				return false, nil
			}
			return false, fmt.Errorf("portscan: removing the nftables table left by %s: %w", owner, err)
		}
		return true, nil
	}
	return false, nil
}

func (b *NftBlocker) setup() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.setupLocked()
}

// setupLocked installs the table, chain, sets and rules, and reinstalls
// everything this blocker believes is blocked. b.mu must be held throughout:
// releasing it during a rebuild would let Close find nothing to delete while
// the rebuild reinstalled the table behind the departing daemon.
func (b *NftBlocker) setupLocked() error {
	// Start from a known state: a table left by a previous instance is deleted,
	// not adopted. AddRule appends, so adopting it would add two drop rules on every
	// start, and its set elements are drops this process knows nothing about. A
	// table whose owner token names a live process is not deleted; this refuses to
	// start instead.
	if tables, err := b.conn.ListTablesOfFamily(nftables.TableFamilyINet); err == nil {
		for _, old := range tables {
			if old.Name != nftTableName {
				continue
			}
			if owner, ok := b.tableOwner(old); ok && owner != b.owner && ownerIsAlive(owner) {
				return fmt.Errorf("%w (%s); refusing to take over its table",
					ErrTableOwnedByLiveInstance, owner)
			}
			b.conn.DelTable(old)
		}
		// A failure here means there was nothing to delete, which is the
		// ordinary case on a clean machine.
		_ = b.conn.Flush()
	}

	b.table = b.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   nftTableName,
	})

	// Priority just below the standard filter hook, so a scanner is dropped
	// before any other input rule has to look at it, while still leaving the
	// administrator's own filter table in charge of everything else.
	prio := *nftables.ChainPriorityFilter - 10
	b.chain = b.conn.AddChain(&nftables.Chain{
		Name:     nftChainName,
		Table:    b.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &prio,
		// The chain's policy stays ACCEPT: this chain exists only to drop the
		// sources in its sets. A DROP policy here would silently become a
		// default-deny input firewall, which is emphatically not what enabling
		// port scan detection asked for.
		Policy: chainPolicyAccept(),
	})

	b.setV4 = &nftables.Set{
		Table:      b.table,
		Name:       nftSetV4Name,
		KeyType:    nftables.TypeIPAddr,
		HasTimeout: true,
		Timeout:    b.timeout,
	}
	if err := b.conn.AddSet(b.setV4, nil); err != nil {
		return fmt.Errorf("portscan: creating the IPv4 source set: %w", err)
	}
	b.setV6 = &nftables.Set{
		Table:      b.table,
		Name:       nftSetV6Name,
		KeyType:    nftables.TypeIP6Addr,
		HasTimeout: true,
		Timeout:    b.timeout,
	}
	if err := b.conn.AddSet(b.setV6, nil); err != nil {
		return fmt.Errorf("portscan: creating the IPv6 source set: %w", err)
	}

	// ip saddr @portscan_sources_v4 drop
	b.conn.AddRule(&nftables.Rule{
		Table: b.table,
		Chain: b.chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // IPv4 source address
				Len:          4,
			},
			&expr.Lookup{SourceRegister: 1, SetName: nftSetV4Name, SetID: b.setV4.ID},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
		UserData: []byte(nftRuleComment + "\n" + b.owner),
	})

	// ip6 saddr @portscan_sources_v6 drop
	b.conn.AddRule(&nftables.Rule{
		Table: b.table,
		Chain: b.chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       8, // IPv6 source address
				Len:          16,
			},
			&expr.Lookup{SourceRegister: 1, SetName: nftSetV6Name, SetID: b.setV6.ID},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
		UserData: []byte(nftRuleComment + "\n" + b.owner),
	})

	// Reinstall what this blocker believes is blocked, the first unblockBatch
	// in the same transaction as the objects that hold them, the rest in
	// transactions of unblockBatch. As lists, not one message per element:
	// with a few hundred messages in one transaction the acknowledgements
	// would be lost and the commit would never return, with this lock held;
	// a few thousand would not fit in one send.
	now := b.now()
	var restore []netip.Addr
	for addr, deadline := range b.live {
		if !deadline.After(now) {
			delete(b.live, addr)
			continue
		}
		if _, _, err := b.setAndKey(addr); err != nil {
			delete(b.live, addr)
			continue
		}
		restore = append(restore, addr)
	}
	first := restore[:min(len(restore), unblockBatch)]
	if err := b.addElementsLocked(first, now); err != nil {
		return err
	}
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("portscan: installing the nftables objects: %w", err)
	}
	b.ready = true
	for start := len(first); start < len(restore); start += unblockBatch {
		chunk := restore[start:min(start+unblockBatch, len(restore))]
		if err := b.addElementsLocked(chunk, now); err != nil {
			return err
		}
		if err := b.conn.Flush(); err != nil {
			return fmt.Errorf("portscan: restoring %d block(s): %w", len(chunk), err)
		}
	}
	return nil
}

// addElementsLocked queues the elements of addrs, with the time each has
// left, as one list per set.
func (b *NftBlocker) addElementsLocked(addrs []netip.Addr, now time.Time) error {
	var v4, v6 []nftables.SetElement
	for _, addr := range addrs {
		set, key, err := b.setAndKey(addr)
		if err != nil {
			continue
		}
		el := nftables.SetElement{Key: key, Timeout: b.live[addr].Sub(now)}
		if set == b.setV4 {
			v4 = append(v4, el)
		} else {
			v6 = append(v6, el)
		}
	}
	if len(v4) > 0 {
		if err := b.conn.SetAddElements(b.setV4, v4); err != nil {
			return fmt.Errorf("portscan: restoring %d IPv4 block(s): %w", len(v4), err)
		}
	}
	if len(v6) > 0 {
		if err := b.conn.SetAddElements(b.setV6, v6); err != nil {
			return fmt.Errorf("portscan: restoring %d IPv6 block(s): %w", len(v6), err)
		}
	}
	return nil
}

// ownerToken identifies this process well enough for another instance to tell
// whether it still runs: PID, start time and boot id, since PIDs are reused.
// Without /proc the token is empty, and an empty token is never treated as
// live.
func ownerToken() string {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	start, err := procStartTime(os.Getpid())
	if err != nil {
		return ""
	}
	return fmt.Sprintf("owner boot=%s pid=%d start=%s",
		strings.TrimSpace(string(boot)), os.Getpid(), start)
}

// ownerIsAlive reports whether the process named by a token is still running.
func ownerIsAlive(token string) bool {
	fields := strings.Fields(token)
	if len(fields) != 4 || fields[0] != "owner" {
		return false
	}
	boot := strings.TrimPrefix(fields[1], "boot=")
	start := strings.TrimPrefix(fields[3], "start=")
	pid, err := strconv.Atoi(strings.TrimPrefix(fields[2], "pid="))
	if err != nil || pid <= 0 {
		return false
	}
	// A token from another boot names a process that cannot exist: the PID may
	// well be in use now, by something entirely unrelated.
	cur, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(cur)) != boot {
		return false
	}
	got, err := procStartTime(pid)
	if err != nil {
		return false
	}
	return got == start
}

// procStartTime returns field 22 of /proc/<pid>/stat, the process start time in
// clock ticks since boot. Together with the PID it survives PID reuse.
func procStartTime(pid int) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	// The second field is the executable name in parentheses and may itself
	// contain spaces and parentheses, so fields are counted from the LAST ')'.
	end := strings.LastIndex(string(raw), ")")
	if end < 0 {
		return "", fmt.Errorf("portscan: /proc/%d/stat is malformed", pid)
	}
	fields := strings.Fields(string(raw[end+1:]))
	// After the ')' the first field is state, which is field 3; start time is
	// field 22, so index 22-3 = 19.
	if len(fields) < 20 {
		return "", fmt.Errorf("portscan: /proc/%d/stat has %d fields after the name", pid, len(fields))
	}
	return fields[19], nil
}

// tableOwner reads the owner token out of the drop rules in an existing table.
func (b *NftBlocker) tableOwner(t *nftables.Table) (string, bool) {
	chains, err := b.conn.ListChainsOfTableFamily(t.Family)
	if err != nil {
		return "", false
	}
	for _, c := range chains {
		if c.Table == nil || c.Table.Name != t.Name || c.Name != nftChainName {
			continue
		}
		rules, err := b.conn.GetRules(t, c)
		if err != nil {
			return "", false
		}
		for _, r := range rules {
			parts := strings.SplitN(string(r.UserData), "\n", 2)
			if len(parts) == 2 && parts[0] == nftRuleComment && parts[1] != "" {
				return parts[1], true
			}
		}
	}
	return "", false
}

func chainPolicyAccept() *nftables.ChainPolicy {
	p := nftables.ChainPolicyAccept
	return &p
}

// Block adds addr to the matching set, or, when it is already there, restarts
// its timeout.
func (b *NftBlocker) Block(addr netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready {
		return fmt.Errorf("portscan: the nftables blocker is not initialised")
	}
	set, key, err := b.setAndKey(addr)
	if err != nil {
		return err
	}
	if _, ok := b.live[normalizeAddr(addr)]; ok {
		// Adding an element that is already there leaves its timeout as it
		// was, and the kernel would release a block the daemon has just
		// extended. It is replaced instead, in one transaction.
		_ = b.conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}})
		_ = b.conn.SetAddElements(set, []nftables.SetElement{{Key: key, Timeout: b.timeout}})
		if err := b.conn.Flush(); err == nil {
			b.live[normalizeAddr(addr)] = b.now().Add(b.timeout)
			return nil
		}
		// Gone from the kernel (deleted from outside, or with its table):
		// installed afresh below.
	}
	if err := b.conn.SetAddElements(set, []nftables.SetElement{{Key: key, Timeout: b.timeout}}); err != nil {
		return fmt.Errorf("portscan: adding %s to %s: %w", addr, set.Name, err)
	}
	err = b.conn.Flush()
	if err == nil {
		b.live[normalizeAddr(addr)] = b.now().Add(b.timeout)
		return nil
	}

	// The table can vanish under us (`nft flush ruleset`). One rebuild is
	// attempted; if it fails the error is returned for the monitor to surface,
	// rather than retried for ever.
	if !isNotExist(err) {
		return fmt.Errorf("portscan: committing the block for %s: %w", addr, err)
	}
	// The lock is held throughout. setupLocked reinstalls every element in
	// b.live along with the objects, so a rebuild restores the protection the
	// daemon claims to be applying rather than starting from two empty sets.
	b.ready = false
	if rebuildErr := b.setupLocked(); rebuildErr != nil {
		return fmt.Errorf("portscan: the nftables table disappeared and could not be rebuilt: %w", rebuildErr)
	}

	set, key, err = b.setAndKey(addr)
	if err != nil {
		return err
	}
	if err := b.conn.SetAddElements(set, []nftables.SetElement{{Key: key, Timeout: b.timeout}}); err != nil {
		return fmt.Errorf("portscan: adding %s to %s after rebuilding: %w", addr, set.Name, err)
	}
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("portscan: committing the block for %s after rebuilding: %w", addr, err)
	}
	b.live[normalizeAddr(addr)] = b.now().Add(b.timeout)
	return nil
}

// Repair rebuilds the table, with every block in force, if something outside
// the daemon removed it or emptied its chain. See BlockManager.ExpireDue.
func (b *NftBlocker) Repair() (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false, nil
	}
	if b.ready {
		intact, err := b.intactLocked()
		if err != nil {
			return false, fmt.Errorf("portscan: checking the nftables table: %w", err)
		}
		if intact {
			return false, nil
		}
	}
	// Not ready either means the table was found gone and a rebuild failed;
	// this retries it.
	b.ready = false
	if err := b.setupLocked(); err != nil {
		return false, fmt.Errorf("portscan: the nftables table disappeared and could not be rebuilt: %w", err)
	}
	return true, nil
}

// intactLocked reports whether the table is still there with both drop rules
// in its chain. `nft flush ruleset` removes the table; `nft flush table`
// leaves it and removes the rules.
func (b *NftBlocker) intactLocked() (bool, error) {
	tables, err := b.conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, err
	}
	found := false
	for _, t := range tables {
		found = found || t.Name == nftTableName
	}
	if !found {
		return false, nil
	}
	rules, err := b.conn.GetRules(b.table, b.chain)
	if err != nil {
		if isNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return len(rules) == 2, nil
}

// Unblock removes addr from the matching set. Removing an element that is not
// there is not an error: the kernel timeout may already have expired it, and a
// caller releasing a block should not have to care which of the two happened
// first.
func (b *NftBlocker) Unblock(addr netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Forget it first, and unconditionally: whatever happens below, this
	// blocker must not reinstall on the next rebuild an address the caller has
	// asked it to release.
	delete(b.live, normalizeAddr(addr))
	if !b.ready {
		// Not ready means setup failed and there is no table, so there is no
		// element to remove and nothing is being dropped. A rebuild holds the
		// lock for its whole duration, so it cannot be half done here.
		return nil
	}
	set, key, err := b.setAndKey(addr)
	if err != nil {
		return err
	}
	if err := b.conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}}); err != nil {
		// Fall through to Flush anyway; the element being absent is the
		// expected outcome of a race with the kernel timeout.
		_ = err
	}
	if err := b.conn.Flush(); err != nil {
		// Only absence is tolerated, the expected outcome of racing the kernel
		// timeout. Any other failure means the element may still be there, dropping
		// traffic this process no longer knows about, and must be reported.
		if isNotExist(err) {
			return nil
		}
		return fmt.Errorf("portscan: releasing the block for %s: %w", addr, err)
	}
	return nil
}

// isNotExist reports whether err is nftables saying the object is not there.
func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT)
}

// UnblockMany releases several addresses in a single nftables transaction (see
// ManyUnblocker): one SetDeleteElements per address family, one Flush.
func (b *NftBlocker) UnblockMany(addrs []netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Forget them first and unconditionally, exactly as Unblock does: whatever
	// the kernel says below, this blocker must not reinstall on its next
	// rebuild an address the caller has asked it to release.
	for _, a := range addrs {
		delete(b.live, normalizeAddr(a))
	}
	if !b.ready {
		return nil
	}

	// One transaction per unblockBatch addresses: past what one list holds
	// the release would silently do nothing (see unblockBatch), and past what
	// one netlink message holds it would fail ("message too long"), leaving
	// the caller's fallback, one transaction per address, to take minutes.
	var firstErr error
	for start := 0; start < len(addrs); start += unblockBatch {
		end := min(start+unblockBatch, len(addrs))
		if err := b.unblockBatchLocked(addrs[start:end]); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// unblockBatch bounds the addresses released, or restored by a rebuild, in
// one transaction. A set's element list is one netlink attribute, whose
// length is 16 bits, and the netlink library truncates a longer one without
// an error: the kernel then deletes or adds none or part of the elements,
// and mostly answers success. Measured, the largest lists that fit: deleting
// 4095 IPv4 or 2340 IPv6 elements, adding 2340 IPv4 or 1638 IPv6 elements
// with a timeout, the rebuild's case. 1024 keeps under all of them, at no
// measurable cost (25 000 released in about a quarter of a second, 65 536
// restored in under 200 ms).
const unblockBatch = 1024

func (b *NftBlocker) unblockBatchLocked(addrs []netip.Addr) error {
	var v4, v6 []nftables.SetElement
	for _, a := range addrs {
		set, key, err := b.setAndKey(a)
		if err != nil {
			// One malformed address must not cost the rest of the batch their
			// release; it is simply not in any set to begin with.
			continue
		}
		if set == b.setV4 {
			v4 = append(v4, nftables.SetElement{Key: key})
		} else {
			v6 = append(v6, nftables.SetElement{Key: key})
		}
	}
	if len(v4) == 0 && len(v6) == 0 {
		return nil
	}

	if len(v4) > 0 {
		// Absence is the expected outcome of racing the kernel-side timeout, so
		// the error is carried to the Flush rather than aborting here.
		_ = b.conn.SetDeleteElements(b.setV4, v4)
	}
	if len(v6) > 0 {
		_ = b.conn.SetDeleteElements(b.setV6, v6)
	}
	if err := b.conn.Flush(); err != nil {
		if !isNotExist(err) {
			return fmt.Errorf("portscan: releasing %d block(s): %w", len(addrs), err)
		}
		if len(addrs) == 1 {
			return nil
		}
		// One element already gone (the kernel timeout won, or someone
		// deleted it) fails the whole transaction: the others are still
		// there. Each is released on its own, where absence is no error.
		for _, a := range addrs {
			if err := b.unblockBatchLocked([]netip.Addr{a}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *NftBlocker) setAndKey(addr netip.Addr) (*nftables.Set, []byte, error) {
	addr = normalizeAddr(addr)
	if !addr.IsValid() {
		return nil, nil, fmt.Errorf("portscan: invalid address")
	}
	if addr.Is4() {
		a := addr.As4()
		return b.setV4, net.IP(a[:]).To4(), nil
	}
	a := addr.As16()
	return b.setV6, a[:], nil
}

// Close removes everything this blocker installed by deleting the whole
// table, so no rule or element survives the daemon.
func (b *NftBlocker) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	b.ready = false
	b.live = map[netip.Addr]time.Time{}

	// The table is deleted by name, whether or not this blocker thinks it is
	// ready: a failed setup may have installed it before failing on a later object.
	b.conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTableName})
	if err := b.conn.Flush(); err != nil {
		if isNotExist(err) {
			// Nothing to remove, which is the outcome this asked for.
			return nil
		}
		return fmt.Errorf("portscan: removing the nftables table: %w", err)
	}
	return nil
}

var _ Blocker = (*NftBlocker)(nil)
