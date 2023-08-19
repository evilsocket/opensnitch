//go:build linux && go1.13
// +build linux,go1.13

package nltest_test

import (
	"errors"
	"os"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func TestLinuxDialError(t *testing.T) {
	c := nltest.Dial(func(req []netlink.Message) ([]netlink.Message, error) {
		return nltest.Error(int(unix.ENOENT), req)
	})

	if _, err := c.Execute(netlink.Message{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected error is not exist, but got: %v", err)
	}
}

func TestLinuxSyscallError(t *testing.T) {
	c := nltest.Dial(func(req []netlink.Message) ([]netlink.Message, error) {
		return nil, unix.ENOENT
	})

	_, err := c.Execute(netlink.Message{})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected error is not exist, but got: %v", err)
	}

	// Expect raw system call errors to be wrapped.
	var serr *os.SyscallError
	if !errors.As(err, &serr) {
		t.Fatalf("error did not contain *os.SyscallError")
	}
	if serr.Err != unix.ENOENT {
		t.Fatalf("expected ENOENT, but got: %v", serr.Err)
	}
}
