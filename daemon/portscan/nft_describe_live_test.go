//go:build linux

package portscan

import (
	"errors"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// What Describe shows the user is presented as the firewall's own listing, so
// it is checked against the firewall's own listing: nft, an independent
// reader, run on the same table.

var nftExpires = regexp.MustCompile(`expires [0-9dhms]+`)

// nftTableListing is `nft list table` for the blocker's table, with the
// countdowns blanked: they move between two reads.
func nftTableListing(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", "inet", nftTableName).CombinedOutput()
	if err != nil {
		nftSkipf(t, "the nft command line is unavailable: %v: %s", err, out)
	}
	return nftExpires.ReplaceAllString(string(out), "expires X")
}

// withoutOtherFamily removes from an nft listing the set and the drop rule of
// the family addr is not in, which is what Describe leaves out.
func withoutOtherFamily(listing string, addr netip.Addr) string {
	otherSet, otherRule := nftSetV6Name, "ip6 saddr @"
	if addr.Is6() {
		otherSet, otherRule = nftSetV4Name, "ip saddr @"
	}
	var out []string
	lines := strings.Split(listing, "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "set "+otherSet+" {" {
			for i < len(lines) && strings.TrimSpace(lines[i]) != "}" {
				i++
			}
			i++ // the blank line after the set
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), otherRule) {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func TestNftDescribeIsWhatNftLists(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	v4 := netip.MustParseAddr("192.0.2.77")
	v6 := netip.MustParseAddr("2001:db8::7")
	for _, a := range []netip.Addr{v4, v6} {
		if err := b.Block(a); err != nil {
			t.Fatalf("Block(%s): %v", a, err)
		}
	}
	listing := nftTableListing(t)
	for _, a := range []netip.Addr{v4, v6} {
		got, err := b.Describe(a)
		if err != nil {
			t.Fatalf("Describe(%s): %v", a, err)
		}
		got = nftExpires.ReplaceAllString(got, "expires X")
		want := withoutOtherFamily(listing, a)
		if got != want {
			t.Fatalf("Describe(%s) is not what nft lists.\ngot:\n%s\nwant:\n%s", a, got, want)
		}
	}
}

// TestNftDescribeShowsAnElementOwnTimeout: an element reinstalled by a
// rebuild carries the time it had left, not the set's timeout, and nft shows
// it. Describe must too, or the dialog would claim the full duration.
func TestNftDescribeShowsAnElementOwnTimeout(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	a := netip.MustParseAddr("192.0.2.78")
	if err := b.Block(a); err != nil {
		t.Fatalf("Block: %v", err)
	}
	b.mu.Lock()
	b.live[a] = b.now().Add(20 * time.Minute)
	b.mu.Unlock()
	if out, err := exec.Command("nft", "delete", "table", "inet", nftTableName).CombinedOutput(); err != nil {
		t.Fatalf("nft delete table: %v: %s", err, out)
	}
	if rebuilt, err := b.Repair(); err != nil || !rebuilt {
		t.Fatalf("Repair = %v, %v; want a rebuild", rebuilt, err)
	}
	got, err := b.Describe(a)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if !strings.Contains(got, a.String()+" timeout 19m59s") && !strings.Contains(got, a.String()+" timeout 20m") {
		t.Fatalf("the element's own timeout is not shown:\n%s", got)
	}
	got = nftExpires.ReplaceAllString(got, "expires X")
	if want := withoutOtherFamily(nftTableListing(t), a); got != want {
		t.Fatalf("Describe is not what nft lists.\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// TestNftDescribeShowsOnlyTheAddress: the dialog is about one block; the
// other addresses of the set are not listed in it.
func TestNftDescribeShowsOnlyTheAddress(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	a, other := netip.MustParseAddr("192.0.2.79"), netip.MustParseAddr("192.0.2.80")
	for _, x := range []netip.Addr{a, other} {
		if err := b.Block(x); err != nil {
			t.Fatalf("Block(%s): %v", x, err)
		}
	}
	got, err := b.Describe(a)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if !strings.Contains(got, "elements = { "+a.String()+" expires ") {
		t.Fatalf("the address is not the element shown:\n%s", got)
	}
	if strings.Contains(got, other.String()) {
		t.Fatalf("another blocked address is shown:\n%s", got)
	}
}

// TestNftDescribeReportsWhatIsMissing: what the firewall no longer holds is
// reported as missing, not rendered from memory.
func TestNftDescribeReportsWhatIsMissing(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	a := netip.MustParseAddr("192.0.2.81")
	if err := b.Block(a); err != nil {
		t.Fatalf("Block: %v", err)
	}
	out, err := exec.Command("nft", "delete", "element", "inet", nftTableName, nftSetV4Name,
		"{ "+a.String()+" }").CombinedOutput()
	if err != nil {
		t.Fatalf("nft delete element: %v: %s", err, out)
	}
	if _, err := b.Describe(a); !errors.Is(err, ErrNotInFirewall) {
		t.Fatalf("Describe of an element removed behind the blocker's back = %v, want ErrNotInFirewall", err)
	}

	if err := b.Block(a); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if out, err := exec.Command("nft", "flush", "chain", "inet", nftTableName, nftChainName).CombinedOutput(); err != nil {
		t.Fatalf("nft flush chain: %v: %s", err, out)
	}
	if _, err := b.Describe(a); err == nil || !strings.Contains(err.Error(), "no rule") {
		t.Fatalf("Describe with the drop rules gone = %v, want the missing rule reported", err)
	}

	if out, err := exec.Command("nft", "delete", "table", "inet", nftTableName).CombinedOutput(); err != nil {
		t.Fatalf("nft delete table: %v: %s", err, out)
	}
	if _, err := b.Describe(a); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("Describe with the table gone = %v, want the missing table reported", err)
	}
}

// TestNftDescribeShowsAForeignRuleWhereItIs: a rule someone else put before
// the drop may accept the address first; the excerpt places it there and
// says so, rather than presenting the drop as what happens.
func TestNftDescribeShowsAForeignRuleWhereItIs(t *testing.T) {
	b := newLiveBlocker(t, time.Hour)
	a := netip.MustParseAddr("192.0.2.82")
	if err := b.Block(a); err != nil {
		t.Fatalf("Block: %v", err)
	}
	out, err := exec.Command("nft", "insert", "rule", "inet", nftTableName, nftChainName,
		"ip", "saddr", "@"+nftSetV4Name, "accept").CombinedOutput()
	if err != nil {
		t.Fatalf("nft insert rule: %v: %s", err, out)
	}
	got, err := b.Describe(a)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	foreign := strings.Index(got, "# a rule not installed by OpenSnitch")
	drop := strings.Index(got, "ip saddr @"+nftSetV4Name+" drop")
	if foreign < 0 || drop < 0 || foreign > drop {
		t.Fatalf("the foreign rule is not shown before the drop:\n%s", got)
	}
	if !strings.Contains(got, "may accept or redirect this address before it is dropped") {
		t.Fatalf("no warning that the drop may not apply:\n%s", got)
	}
}
