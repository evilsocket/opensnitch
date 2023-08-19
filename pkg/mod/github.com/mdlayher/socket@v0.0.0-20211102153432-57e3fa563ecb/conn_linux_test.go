//go:build linux
// +build linux

package socket_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

func TestLinuxConnBuffers(t *testing.T) {
	// This test isn't necessarily Linux-specific but it's easiest to verify on
	// Linux because we can rely on the kernel's documented buffer size
	// manipulation behavior.
	c, err := socket.Socket(unix.AF_INET, unix.SOCK_STREAM, 0, "tcpv4")
	if err != nil {
		t.Fatalf("failed to open socket: %v", err)
	}
	defer c.Close()

	const (
		set = 8192

		// Per socket(7):
		//
		// "The kernel doubles this value (to allow space for
		// book‐keeping overhead) when it is set using setsockopt(2),
		// and this doubled value is returned by getsockopt(2).""
		want = set * 2
	)

	if err := c.SetReadBuffer(set); err != nil {
		t.Fatalf("failed to set read buffer size: %v", err)
	}

	if err := c.SetWriteBuffer(set); err != nil {
		t.Fatalf("failed to set write buffer size: %v", err)
	}

	// Now that we've set the buffers, we can check the size by asking the
	// kernel using SyscallConn and getsockopt.

	rcv, err := c.ReadBuffer()
	if err != nil {
		t.Fatalf("failed to get read buffer size: %v", err)
	}

	snd, err := c.WriteBuffer()
	if err != nil {
		t.Fatalf("failed to get write buffer size: %v", err)
	}

	if diff := cmp.Diff(want, rcv); diff != "" {
		t.Fatalf("unexpected read buffer size (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want, snd); diff != "" {
		t.Fatalf("unexpected write buffer size (-want +got):\n%s", diff)
	}
}
