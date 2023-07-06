package nftest

import (
	"os"
	"runtime"
	"testing"

	nftb "github.com/evilsocket/opensnitch/daemon/firewall/nftables"
	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

var (
	conn  *nftables.Conn
	newNS netns.NsHandle

	// Fw represents the nftables Fw object.
	Fw, _ = nftb.Fw()
)

func init() {
	nftb.InitMapsStore()
}

// SkipIfNotPrivileged will skip the test from where it's invoked,
// to skip the test if we don't have root privileges.
// This may occur when executing the tests on restricted environments,
// such as containers, chroots, etc.
func SkipIfNotPrivileged(t *testing.T) {
	if os.Getenv("PRIVILEGED_TESTS") == "" {
		t.Skip("Set PRIVILEGED_TESTS to 1 to launch these tests, and launch them as root, or as a user allowed to create new namespaces.")
	}
}

// OpenSystemConn opens a new connection with the kernel in a new namespace.
// https://github.com/google/nftables/blob/8f2d395e1089dea4966c483fbeae7e336917c095/internal/nftest/system_conn.go#L15
func OpenSystemConn(t *testing.T) (*nftables.Conn, netns.NsHandle) {
	t.Helper()
	// We lock the goroutine into the current thread, as namespace operations
	// such as those invoked by `netns.New()` are thread-local. This is undone
	// in nftest.CleanupSystemConn().
	runtime.LockOSThread()

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New() failed: %v", err)
	}
	t.Log("OpenSystemConn() with NS:", ns)
	c, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatalf("nftables.New() failed: %v", err)
	}
	return c, ns
}

// CleanupSystemConn closes the given namespace.
func CleanupSystemConn(t *testing.T, newNS netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := newNS.Close(); err != nil {
		t.Fatalf("newNS.Close() failed: %v", err)
	}
}
