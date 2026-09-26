//go:build linux

package portscan

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestVerifyTrustedPathRefusesAWritablePath guards the reachable half of a
// weakness in OpenSnitch's existing module search.
//
// core.LoadEbpfModule searches /usr/local/lib/opensnitchd/ebpf first, and on
// Debian and Ubuntu base-files ships /usr/local and /usr/local/lib as root:staff
// mode 2775 -- group-writable by design. For the modules that are packaged, an
// attacker has to beat a real file that the daemon would load anyway. For this
// one there is nothing to beat: no package installs opensnitch-scan.o, so a file
// dropped there is the only one the search finds. A BPF program at TC ingress
// can read, rewrite, drop and redirect every inbound packet, so that is a
// complete machine-in-the-middle obtained from an unprivileged account.
func TestVerifyTrustedPathRefusesAWritablePath(t *testing.T) {
	// The test's own temporary directory is owned by the test user, which is
	// exactly the shape being refused.
	dir := t.TempDir()
	mod := filepath.Join(dir, ScanModuleName)
	if err := os.WriteFile(mod, []byte("not really an object"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := verifyTrustedPath(mod)
	if err == nil {
		t.Fatal("a module under a directory owned by an unprivileged user was accepted")
	}
	// Either reason is the right one: the temporary tree is under /tmp, which is
	// world-writable, and is itself owned by the test user when that user is not
	// root. What matters is that the walk names the component it refused.
	if !strings.Contains(err.Error(), "owned by uid") &&
		!strings.Contains(err.Error(), "writable by group or other") {
		t.Errorf("error = %v, want it to name the ownership or the mode", err)
	}
	t.Logf("refused as it should be: %v", err)
}

// TestVerifyTrustedPathAcceptsASystemPath: the check must not refuse everything.
// /usr/lib is root-owned and not group-writable on any sane system, so if the
// walk rejects it the check is useless rather than strict.
func TestVerifyTrustedPathAcceptsASystemPath(t *testing.T) {
	// Meaningless inside a uid-mapped user namespace, where the files that
	// belong to root outside appear as nobody. The privileged harness runs the
	// whole package in such a namespace, so this has to say so rather than fail.
	if fi, err := os.Stat("/"); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			t.Skipf("/ is owned by uid %d here: this is a uid-mapped namespace,"+
				" where root ownership cannot be observed", st.Uid)
		}
	}

	for _, p := range []string{"/usr/lib", "/usr", "/"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := verifyTrustedPath(p); err != nil {
			t.Errorf("verifyTrustedPath(%s) = %v; a standard system directory must pass", p, err)
		}
	}
}

// TestResolveScanModuleVerifiesAnExplicitPath: a directory named in the
// configuration is an operator's instruction, but it is still verified.
//
// Taking it on trust would rest on the premise that the configuration file is
// root-owned and so whatever it names is root's choice. That premise does not
// hold: the daemon rewrites that file on a CHANGE_CONFIG notification from the
// user interface, over a channel that authenticates nobody. Pointing
// ModulesPath at a directory anyone can write to would have a root daemon load
// an arbitrary BPF program and attach it to TC ingress.
func TestResolveScanModuleVerifiesAnExplicitPath(t *testing.T) {
	// A root-owned system directory is honoured.
	const trusted = "/usr/lib"
	if _, err := os.Stat(trusted); err == nil {
		got, err := resolveScanModule(trusted)
		if err != nil {
			t.Fatalf("resolveScanModule(%s): %v; a root-owned directory must be honoured", trusted, err)
		}
		if got != trusted {
			t.Errorf("resolveScanModule returned %q, want the configured %q", got, trusted)
		}
	}

	// One we own is not.
	dir := t.TempDir()
	if _, err := resolveScanModule(dir); err == nil {
		t.Fatalf("resolveScanModule(%s) accepted a directory owned by this user:"+
			" a root daemon would load whatever was placed there", dir)
	}
}

// TestScanModuleSearchPathPrefersThePackageDirectory pins the ordering, which
// is the other half of that protection: the group-writable location is
// searched last, not first as core.LoadEbpfModule does.
func TestScanModuleSearchPathPrefersThePackageDirectory(t *testing.T) {
	if len(scanModuleSearchPath) == 0 {
		t.Fatal("the search path is empty")
	}
	if scanModuleSearchPath[0] != "/usr/lib/opensnitchd/ebpf" {
		t.Errorf("the first path searched is %q, want the package directory",
			scanModuleSearchPath[0])
	}
	local := -1
	pkg := -1
	for i, p := range scanModuleSearchPath {
		if strings.HasPrefix(p, "/usr/local/") {
			local = i
		}
		if p == "/usr/lib/opensnitchd/ebpf" {
			pkg = i
		}
	}
	if local >= 0 && local < pkg {
		t.Errorf("%q is searched before the package directory", scanModuleSearchPath[local])
	}
}
