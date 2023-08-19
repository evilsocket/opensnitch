//go:build linux
// +build linux

package netlink

import (
	"testing"
)

func TestNetNSDisabled(t *testing.T) {
	// Attempt to open a non-existent file as a netns descriptor.
	netns, err := fileNetNS("/netlinktestdoesnotexist")
	if err != nil {
		t.Fatal("unexpected error opening dummy netns file", err)
	}
	if !netns.disabled {
		t.Fatal("expected netNS to have disabled flag set")
	}

	// do skips invoking its argument when netns.disabled is set.
	_ = netns.do(
		func() error {
			t.Fatal("this function should never execute when netns are disabled")
			return nil
		})

	if netns.FD() > 0 {
		t.Fatal("expected invalid netns fd when netns are disabled")
	}
}

func TestThreadNetNS(t *testing.T) {
	netns, err := threadNetNS()
	if err != nil {
		t.Fatal("error getting thread's network namespace:", err)
	}

	if netns.FD() < 0 {
		t.Fatal("expected valid netns fd (> 0)")
	}

	if err := netns.Close(); err != nil {
		t.Fatal("error closing netns handle:", err)
	}
}
