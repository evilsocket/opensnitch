// +build linux

package netlink

import (
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/vishvananda/netns"
)

// TestNetNsIdByFd tests setting and getting the network namespace ID
// by file descriptor. It opens a namespace fd, sets it to a random id,
// then retrieves the ID.
// This does not do any namespace switching.
func TestNetNsIdByFd(t *testing.T) {
	skipUnlessRoot(t)
	// create a network namespace
	ns, err := netns.New()
	CheckErrorFail(t, err)

	// set its ID
	// In an attempt to avoid namespace id collisions, set this to something
	// insanely high. When the kernel assigns IDs, it does so starting from 0
	// So, just use our pid shifted up 16 bits
	wantID := os.Getpid() << 16

	h, err := NewHandle()
	CheckErrorFail(t, err)
	err = h.SetNetNsIdByFd(int(ns), wantID)
	CheckErrorFail(t, err)

	// Get the ID back, make sure it matches
	haveID, err := h.GetNetNsIdByFd(int(ns))
	if haveID != wantID {
		t.Errorf("GetNetNsIdByFd returned %d, want %d", haveID, wantID)
	}

	ns.Close()
}

// TestNetNsIdByPid tests manipulating namespace IDs by pid (really, task / thread id)
// Does the same as TestNetNsIdByFd, but we need to change namespaces so we
// actually have a pid in that namespace
func TestNetNsIdByPid(t *testing.T) {
	skipUnlessRoot(t)
	runtime.LockOSThread() // we need a constant OS thread
	origNs, _ := netns.Get()

	// create and enter a new netns
	ns, err := netns.New()
	CheckErrorFail(t, err)
	err = netns.Set(ns)
	CheckErrorFail(t, err)
	// make sure we go back to the original namespace when done
	defer func() {
		err := netns.Set(origNs)
		if err != nil {
			panic("failed to restore network ns, bailing")
		}
		runtime.UnlockOSThread()
	}()

	// As above, we'll pick a crazy large netnsid to avoid collisions
	wantID := syscall.Gettid() << 16

	h, err := NewHandle()
	CheckErrorFail(t, err)
	err = h.SetNetNsIdByPid(syscall.Gettid(), wantID)
	CheckErrorFail(t, err)

	//Get the ID and see if it worked
	haveID, err := h.GetNetNsIdByPid(syscall.Gettid())
	if haveID != wantID {
		t.Errorf("GetNetNsIdByPid returned %d, want %d", haveID, wantID)
	}
}
