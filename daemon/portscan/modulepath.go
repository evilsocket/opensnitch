//go:build linux

package portscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
)

// scanModuleSearchPath is where the eBPF object is looked for when the
// configuration names no directory.
//
// It is not core.LoadEbpfModule's list, which searches
// /usr/local/lib/opensnitchd/ebpf first. On Debian and Ubuntu /usr/local/lib is
// root:staff 2775, writable by the staff group, so a file dropped there could
// be loaded in place of the packaged one, or where no package ships it.
// A program at TC ingress can read, rewrite, drop and redirect every inbound
// packet: that would be a machine-in-the-middle from an unprivileged account.
// The package directory comes first, and every candidate must pass
// verifyTrustedPath.
var scanModuleSearchPath = []string{
	"/usr/lib/opensnitchd/ebpf",
	"/usr/local/lib/opensnitchd/ebpf",
	"/etc/opensnitchd",
}

// resolveScanModule picks the directory to load the module from. A directory
// named in the configuration is verified like any other: the daemon rewrites
// its configuration file on a CHANGE_CONFIG from the user interface, over a
// channel that authenticates nobody.
func resolveScanModule(configured string) (string, error) {
	if configured != "" {
		// The directory, not the file: the directory is what must be root-owned
		// and closed to everyone else, the file inside inherits that, and the
		// file may legitimately not exist yet at this point.
		if err := verifyTrustedPath(configured); err != nil {
			return "", fmt.Errorf("%w: refusing to load %s from the configured"+
				" Ebpf.ModulesPath: %v", ErrEbpfUnavailable, ScanModuleName, err)
		}
		return configured, nil
	}
	var refused []string
	for _, dir := range scanModuleSearchPath {
		full := filepath.Join(dir, ScanModuleName)
		if _, err := os.Stat(full); err != nil {
			continue
		}
		if err := verifyTrustedPath(full); err != nil {
			refused = append(refused, err.Error())
			continue
		}
		return dir, nil
	}
	if len(refused) > 0 {
		// Loud, not silent. A module present but refused is a machine where
		// someone has put a file where the daemon looks, and the administrator
		// needs to be told that rather than left with "detection unavailable".
		return "", fmt.Errorf("%w: refusing to load %s from an untrusted path: %s",
			ErrEbpfUnavailable, ScanModuleName, strings.Join(refused, "; "))
	}
	// Not found anywhere: an error, not an empty string, which would hand the
	// choice to core.LoadEbpfModule's own, unverified search list (see
	// scanModuleSearchPath) and to a second, unchecked path resolution.
	return "", fmt.Errorf("%w: %s was not found in %s; install the OpenSnitch eBPF"+
		" module package, or set Ebpf.ModulesPath to a root-owned directory that"+
		" is not writable by anyone else",
		ErrEbpfUnavailable, ScanModuleName, strings.Join(scanModuleSearchPath, ", "))
}

// verifyTrustedPath reports whether a file and every directory leading to it
// are owned by root and writable by nobody else: a writable directory anywhere
// above lets its owner redirect the lookup.
func verifyTrustedPath(p string) error {
	abs, err := filepath.Abs(p)
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	cur := "/"
	for _, part := range strings.Split(strings.Trim(abs, "/"), "/") {
		cur = filepath.Join(cur, part)
		if err := checkComponent(cur); err != nil {
			return err
		}
	}
	return checkComponent("/")
}

func checkComponent(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its ownership", p)
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not root", p, st.Uid)
	}
	// A symlink is refused outright: the walk checks the components of the path it
	// was given, never the link's target, which is what gets opened. The trusted
	// paths are plain directories on every distribution; an administrator who needs
	// a link can point Ebpf.ModulesPath at the real directory.
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link; the path that is verified must be"+
			" the path that is opened", p)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or other (mode %04o)", p, perm)
	}
	return nil
}

// loadScanModule opens the object, verifies the descriptor it got, and loads
// that same descriptor, so what was checked is what is loaded. O_NOFOLLOW
// refuses a symlink at the final component, and ownership and permissions are
// checked with fstat on the open descriptor: a file swapped afterwards leaves it
// pointing at the verified bytes.
func loadScanModule(dir string) (*ebpf.Collection, error) {
	if err := verifyTrustedPath(dir); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEbpfUnavailable, err)
	}
	full := filepath.Join(dir, ScanModuleName)

	f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: opening %s: %v", ErrEbpfUnavailable, full, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrEbpfUnavailable, full, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrEbpfUnavailable, full)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%w: %s: cannot read its ownership", ErrEbpfUnavailable, full)
	}
	if st.Uid != 0 {
		return nil, fmt.Errorf("%w: %s is owned by uid %d, not root", ErrEbpfUnavailable, full, st.Uid)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return nil, fmt.Errorf("%w: %s is writable by group or other (mode %04o)",
			ErrEbpfUnavailable, full, perm)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %v", ErrEbpfUnavailable, full, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("%w: loading %s: %v", ErrEbpfUnavailable, full, err)
	}
	return coll, nil
}
