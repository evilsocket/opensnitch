//go:build linux

package portscan

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// ErrNotInFirewall is returned by Describe when the firewall does not hold the
// address: the kernel timeout or someone else removed it.
var ErrNotInFirewall = errors.New("portscan: the address is not in the firewall")

// Describe renders, in the syntax of `nft list table inet opensnitch-portscan`,
// the part of the table that drops addr: its set, with addr as the only
// element shown, and the rule of the chain that looks that set up.
//
// Everything is read from the kernel at the time of the call. Rendering what
// this blocker believes it installed would show the user a rule that may no
// longer be there, which is the one thing this view must not do; read back, a
// table someone emptied, or a rule they deleted, shows as missing. The objects
// are this blocker's own, so only their known shapes are rendered; anything
// else in the chain is counted, not interpreted.
func (b *NftBlocker) Describe(addr netip.Addr) (string, error) {
	addr = normalizeAddr(addr)
	if !addr.IsValid() {
		return "", fmt.Errorf("portscan: invalid address")
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return "", fmt.Errorf("portscan: the nftables blocker is closed")
	}
	// One read at a time, on a connection of its own, without b.mu: the
	// reads dump the whole set, which takes over a second at the largest
	// MaxBlockedSources, and a user interface repeating the request must
	// neither stack them up nor hold back the blocks and releases that need
	// b.mu.
	b.describeMu.Lock()
	defer b.describeMu.Unlock()
	conn, err := nftables.New()
	if err != nil {
		return "", fmt.Errorf("portscan: opening a netlink connection to nftables: %w", err)
	}
	defer conn.CloseLasting()

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: nftTableName}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return "", fmt.Errorf("portscan: listing the nftables tables: %w", err)
	}
	found := false
	for _, t := range tables {
		found = found || t.Name == nftTableName
	}
	if !found {
		return "", fmt.Errorf("portscan: the nftables table inet %s is not installed", nftTableName)
	}

	setName := nftSetV4Name
	key := addr.AsSlice()
	if addr.Is6() {
		setName = nftSetV6Name
	}
	set, err := conn.GetSetByName(table, setName)
	if err != nil {
		return "", fmt.Errorf("portscan: reading the set %s: %w", setName, err)
	}
	elems, err := conn.GetSetElements(set)
	if err != nil {
		return "", fmt.Errorf("portscan: reading the elements of %s: %w", setName, err)
	}
	var elem *nftables.SetElement
	for i := range elems {
		if bytes.Equal(elems[i].Key, key) {
			elem = &elems[i]
			break
		}
	}
	if elem == nil {
		return "", fmt.Errorf("%w: %s is not in the set %s", ErrNotInFirewall, addr, setName)
	}

	var chain *nftables.Chain
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return "", fmt.Errorf("portscan: listing the nftables chains: %w", err)
	}
	for _, c := range chains {
		if c.Table != nil && c.Table.Name == nftTableName && c.Name == nftChainName {
			chain = c
		}
	}
	if chain == nil {
		return "", fmt.Errorf("portscan: the chain %s is missing from the table", nftChainName)
	}
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return "", fmt.Errorf("portscan: reading the rules of %s: %w", nftChainName, err)
	}
	// The chain in the kernel's order. A rule this blocker did not install is
	// not interpreted, but it is placed where it is: one above the drop may
	// accept the address first, and the excerpt must not present the drop as
	// what happens to it.
	var lines []string
	drops, foreignAbove := 0, 0
	for _, r := range rules {
		fam, sname, ok := dropRuleShape(r.Exprs)
		switch {
		case ok && sname == setName:
			lines = append(lines, fam+" saddr @"+sname+" drop")
			drops++
		case ok:
			// The other family's rule: it does not apply to this address.
		default:
			lines = append(lines, fmt.Sprintf("# a rule not installed by OpenSnitch (handle %d), not shown", r.Handle))
			if drops == 0 {
				foreignAbove++
			}
		}
	}
	if drops == 0 {
		return "", fmt.Errorf("portscan: no rule in %s drops the sources in %s", nftChainName, setName)
	}

	var s strings.Builder
	fmt.Fprintf(&s, "table inet %s {\n", nftTableName)
	fmt.Fprintf(&s, "\tset %s {\n", setName)
	fmt.Fprintf(&s, "\t\ttype %s\n", set.KeyType.Name)
	if set.HasTimeout && set.Timeout > 0 {
		fmt.Fprintf(&s, "\t\ttimeout %s\n", nftDuration(set.Timeout))
	}
	fmt.Fprintf(&s, "\t\telements = { %s", addr)
	// nft prints an element's own timeout only when it is not the set's.
	if elem.Timeout > 0 && elem.Timeout != set.Timeout {
		fmt.Fprintf(&s, " timeout %s", nftDuration(elem.Timeout))
	}
	if elem.Expires > 0 {
		fmt.Fprintf(&s, " expires %s", nftDuration(elem.Expires))
	}
	s.WriteString(" }\n\t}\n\n")
	fmt.Fprintf(&s, "\tchain %s {\n", nftChainName)
	fmt.Fprintf(&s, "\t\t%s\n", nftChainHeader(chain))
	for _, l := range lines {
		fmt.Fprintf(&s, "\t\t%s\n", l)
	}
	s.WriteString("\t}\n}\n")
	if foreignAbove > 0 {
		fmt.Fprintf(&s, "# Warning: %d rule(s) not installed by OpenSnitch come before the drop,\n"+
			"# and may accept or redirect this address before it is dropped.\n", foreignAbove)
	}
	return s.String(), nil
}

// dropRuleShape recognises the drop rules setupLocked installs and returns
// the family keyword and the set name they look up:
//
//	meta nfproto <family>; payload <saddr> -> reg 1; lookup reg 1 @set; drop
//
// which nft lists as `ip saddr @set drop`.
func dropRuleShape(exprs []expr.Any) (family, set string, ok bool) {
	if len(exprs) != 5 {
		return "", "", false
	}
	meta, ok1 := exprs[0].(*expr.Meta)
	cmp, ok2 := exprs[1].(*expr.Cmp)
	pl, ok3 := exprs[2].(*expr.Payload)
	lk, ok4 := exprs[3].(*expr.Lookup)
	vd, ok5 := exprs[4].(*expr.Verdict)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return "", "", false
	}
	if meta.Key != expr.MetaKeyNFPROTO || cmp.Op != expr.CmpOpEq || len(cmp.Data) != 1 ||
		cmp.Register != meta.Register || pl.Base != expr.PayloadBaseNetworkHeader ||
		pl.DestRegister != meta.Register || lk.SourceRegister != meta.Register || lk.Invert ||
		lk.IsDestRegSet || vd.Kind != expr.VerdictDrop {
		return "", "", false
	}
	switch {
	case cmp.Data[0] == unix.NFPROTO_IPV4 && pl.Offset == 12 && pl.Len == 4:
		return "ip", lk.SetName, true
	case cmp.Data[0] == unix.NFPROTO_IPV6 && pl.Offset == 8 && pl.Len == 16:
		return "ip6", lk.SetName, true
	}
	return "", "", false
}

// nftChainHeader renders a base chain's declaration as nft lists it, for the
// filter chains this blocker creates.
func nftChainHeader(c *nftables.Chain) string {
	hook := "unknown"
	if c.Hooknum != nil {
		switch *c.Hooknum {
		case *nftables.ChainHookPrerouting:
			hook = "prerouting"
		case *nftables.ChainHookInput:
			hook = "input"
		case *nftables.ChainHookForward:
			hook = "forward"
		case *nftables.ChainHookOutput:
			hook = "output"
		case *nftables.ChainHookPostrouting:
			hook = "postrouting"
		}
	}
	prio := "0"
	if c.Priority != nil {
		prio = nftPriority(int32(*c.Priority))
	}
	policy := "accept"
	if c.Policy != nil && *c.Policy == nftables.ChainPolicyDrop {
		policy = "drop"
	}
	return fmt.Sprintf("type %s hook %s priority %s; policy %s;", c.Type, hook, prio, policy)
}

// nftPriority names a filter-family priority the way nft does: relative to the
// standard priority within 10 of it, as a bare number otherwise.
func nftPriority(p int32) string {
	std := []struct {
		name  string
		value int32
	}{
		{"raw", -300}, {"mangle", -150}, {"dstnat", -100},
		{"filter", 0}, {"security", 50}, {"srcnat", 100},
	}
	for _, s := range std {
		switch d := p - s.value; {
		case d == 0:
			return s.name
		case d > 0 && d <= 10:
			return fmt.Sprintf("%s + %d", s.name, d)
		case d < 0 && d >= -10:
			return fmt.Sprintf("%s - %d", s.name, -d)
		}
	}
	return fmt.Sprintf("%d", p)
}

// nftDuration formats a duration as nft does: days, hours, minutes, seconds and
// milliseconds, leaving out the units that are zero.
func nftDuration(d time.Duration) string {
	ms := d.Milliseconds()
	if ms <= 0 {
		return "0s"
	}
	var s strings.Builder
	for _, u := range []struct {
		suffix string
		ms     int64
	}{{"d", 86400000}, {"h", 3600000}, {"m", 60000}, {"s", 1000}, {"ms", 1}} {
		if n := ms / u.ms; n > 0 {
			fmt.Fprintf(&s, "%d%s", n, u.suffix)
			ms -= n * u.ms
		}
	}
	return s.String()
}

var _ Describer = (*NftBlocker)(nil)
