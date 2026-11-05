package rule

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func resetAliasCache() {
	AliasIPCache = make(map[string][]*net.IPNet)
}

func aliasContains(t *testing.T, alias, ip string) bool {
	t.Helper()
	nets, ok := AliasIPCache[alias]
	if !ok {
		t.Errorf("alias %q not loaded", alias)
		return false
	}
	addr := net.ParseIP(ip)
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// When the aliases file is missing (some distributions don't ship it) the
// daemon must still know the aliases the UI offers, otherwise every rule
// with "LAN"/"MULTICAST" as destination fails to compile.
func TestLoadAliasesFallsBackToDefaults(t *testing.T) {
	resetAliasCache()
	defer resetAliasCache()

	if err := LoadAliases(filepath.Join(t.TempDir(), "no-such-aliases.json")); err == nil {
		t.Error("LoadAliases() on a missing file should report the error")
	}

	for alias, ip := range map[string]string{
		"LAN":       "192.168.1.10",
		"MULTICAST": "224.0.0.251",
	} {
		if !aliasContains(t, alias, ip) {
			t.Errorf("default alias %s should contain %s", alias, ip)
		}
	}
	// bare IPv6 loopback in the defaults ("::1") must be usable as /128
	if !aliasContains(t, "LAN", "::1") {
		t.Error("default LAN alias should contain ::1")
	}
	if aliasContains(t, "LAN", "8.8.8.8") {
		t.Error("default LAN alias must not contain public addresses")
	}

	// and a dest.network operator using the alias must compile and match
	var list []Operator
	op, err := NewOperator(Network, false, OpDstNetwork, "LAN", list)
	if err != nil {
		t.Fatal(err)
	}
	if err := op.Compile(); err != nil {
		t.Fatalf("dest.network LAN should compile with default aliases: %v", err)
	}
}

// An invalid aliases file also falls back to the defaults.
func TestLoadAliasesInvalidFileFallsBack(t *testing.T) {
	resetAliasCache()
	defer resetAliasCache()

	path := filepath.Join(t.TempDir(), "broken-aliases.json")
	if err := os.WriteFile(path, []byte("{ not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := LoadAliases(path); err == nil {
		t.Error("LoadAliases() on invalid JSON should report the error")
	}
	if !aliasContains(t, "LAN", "10.1.2.3") {
		t.Error("default LAN alias expected after invalid file")
	}
}

// A valid file replaces the defaults; bare IPs are accepted as /32 or /128.
func TestLoadAliasesFromFile(t *testing.T) {
	resetAliasCache()
	defer resetAliasCache()

	path := filepath.Join(t.TempDir(), "aliases.json")
	content := `{"OFFICE": ["203.0.113.0/24", "198.51.100.7", "2001:db8::1"], "BAD": ["not-a-network"]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := LoadAliases(path); err != nil {
		t.Fatal(err)
	}
	if !aliasContains(t, "OFFICE", "203.0.113.9") {
		t.Error("OFFICE should contain 203.0.113.9")
	}
	if !aliasContains(t, "OFFICE", "198.51.100.7") || aliasContains(t, "OFFICE", "198.51.100.8") {
		t.Error("bare IPv4 should be loaded as a /32")
	}
	if !aliasContains(t, "OFFICE", "2001:db8::1") || aliasContains(t, "OFFICE", "2001:db8::2") {
		t.Error("bare IPv6 should be loaded as a /128")
	}
	if len(AliasIPCache["BAD"]) != 0 {
		t.Error("unparseable entries must be skipped")
	}
	if _, ok := AliasIPCache["LAN"]; ok {
		t.Error("defaults must not be merged when a valid file is loaded")
	}
}
