//go:build linux

package portscan

import (
	"fmt"
	"os"
	"testing"
)

// Tests that change network state -- install nftables tables, flush the
// ruleset, add addresses to lo, create veth and tun devices -- must never run
// against the machine of whoever typed `sudo go test ./...`, which is how the
// rest of the OpenSnitch suite is run. Being root proves nothing about where the
// changes land, so each of them asks for one of two explicit statements:
//
//	PORTSCAN_DISPOSABLE_NETNS=1  this process runs in a network namespace of its
//	                             own (testdata/run_*_test.sh set it under unshare)
//	PORTSCAN_DISPOSABLE_HOST=1   the whole machine is throwaway (the qemu bench,
//	                             a CI runner)
//
// Without either, the test skips -- or fails under the PORTSCAN_REQUIRE_*
// variable that asked for it, so CI cannot pass by skipping.
const (
	envDisposableNetns = "PORTSCAN_DISPOSABLE_NETNS"
	envDisposableHost  = "PORTSCAN_DISPOSABLE_HOST"
)

// requireDisposableNetwork skips unless the test may change network state.
// requireVar names the PORTSCAN_REQUIRE_* variable that turns the skip into a
// failure.
func requireDisposableNetwork(t *testing.T, requireVar string) {
	t.Helper()
	switch verdict, reason := disposableNetwork(os.Getenv, os.Readlink, requireVar); verdict {
	case guardFail:
		t.Fatal(reason)
	case guardSkip:
		t.Skip(reason)
	}
}

type guardVerdict int

const (
	guardAllow guardVerdict = iota
	guardSkip
	guardFail
)

// disposableNetwork is the decision requireDisposableNetwork applies, apart
// from the environment and /proc it reads, so the guard itself can be tested:
// neutralised, it would leave every suite green while the next
// `sudo go test ./...` emptied the maintainer's firewall.
func disposableNetwork(getenv func(string) string, readlink func(string) (string, error),
	requireVar string) (guardVerdict, string) {
	if getenv(envDisposableHost) == "1" {
		return guardAllow, ""
	}
	if getenv(envDisposableNetns) == "1" {
		// The statement is checked where it can be: sharing PID 1's network
		// namespace means the changes would land on the host. Inside an
		// unprivileged user namespace /proc/1/ns/net is not readable, which is
		// itself a sign of isolation, so only a readable, equal link refuses.
		self, errSelf := readlink("/proc/self/ns/net")
		pid1, errPid1 := readlink("/proc/1/ns/net")
		if errSelf == nil && errPid1 == nil && self == pid1 {
			return guardFail, fmt.Sprintf("%s=1 but this process shares PID 1's network namespace (%s):"+
				" refusing to change the host's firewall and interfaces", envDisposableNetns, self)
		}
		return guardAllow, ""
	}
	reason := "this test changes nftables and interfaces, and nothing says this" +
		" network namespace is disposable; run it through testdata/run_*_test.sh," +
		" or set " + envDisposableHost + "=1 on a throwaway machine"
	if requireVar != "" && getenv(requireVar) == "1" {
		return guardFail, fmt.Sprintf("%s=1 but %s", requireVar, reason)
	}
	return guardSkip, reason
}

// TestTheNetworkGuardRefusesTheHost pins the guard's four answers.
func TestTheNetworkGuardRefusesTheHost(t *testing.T) {
	links := func(self, pid1 string) func(string) (string, error) {
		return func(p string) (string, error) {
			if p == "/proc/self/ns/net" {
				return self, nil
			}
			if pid1 == "" {
				return "", os.ErrPermission
			}
			return pid1, nil
		}
	}
	env := func(kv ...string) func(string) string {
		return func(k string) string {
			for i := 0; i+1 < len(kv); i += 2 {
				if kv[i] == k {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	for _, c := range []struct {
		name  string
		env   func(string) string
		links func(string) (string, error)
		want  guardVerdict
	}{
		{"nothing said", env(), links("net:[1]", "net:[1]"), guardSkip},
		{"nothing said, but required", env("PORTSCAN_REQUIRE_NFT", "1"), links("net:[1]", "net:[1]"), guardFail},
		{"a namespace claimed, and it is PID 1's", env(envDisposableNetns, "1"), links("net:[1]", "net:[1]"), guardFail},
		{"a namespace claimed, and it is another", env(envDisposableNetns, "1"), links("net:[2]", "net:[1]"), guardAllow},
		{"a namespace claimed, PID 1's unreadable", env(envDisposableNetns, "1"), links("net:[2]", ""), guardAllow},
		{"a throwaway machine", env(envDisposableHost, "1"), links("net:[1]", "net:[1]"), guardAllow},
	} {
		if got, _ := disposableNetwork(c.env, c.links, "PORTSCAN_REQUIRE_NFT"); got != c.want {
			t.Errorf("%s: verdict %d, want %d", c.name, got, c.want)
		}
	}
}
