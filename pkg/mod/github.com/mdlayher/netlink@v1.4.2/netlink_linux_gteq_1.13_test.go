//go:build linux && go1.13
// +build linux,go1.13

package netlink_test

import (
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mdlayher/ethtool"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestOpErrorUnwrapLinux(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		ok     bool
	}{
		{
			name:   "ENOBUFS",
			err:    unix.ENOBUFS,
			target: os.ErrNotExist,
		},
		{
			name: "OpError ENOBUFS",
			err: &netlink.OpError{
				Op:  "receive",
				Err: unix.ENOBUFS,
			},
			target: os.ErrNotExist,
		},
		{
			name: "OpError os.SyscallError ENOBUFS",
			err: &netlink.OpError{
				Op:  "receive",
				Err: os.NewSyscallError("recvmsg", unix.ENOBUFS),
			},
			target: os.ErrNotExist,
		},
		{
			name:   "ENOENT",
			err:    unix.ENOENT,
			target: os.ErrNotExist,
			ok:     true,
		},
		{
			name: "OpError ENOENT",
			err: &netlink.OpError{
				Op:  "receive",
				Err: unix.ENOENT,
			},
			target: os.ErrNotExist,
			ok:     true,
		},
		{
			name: "OpError os.SyscallError ENOENT",
			err: &netlink.OpError{
				Op:  "receive",
				Err: os.NewSyscallError("recvmsg", unix.ENOENT),
			},
			target: os.ErrNotExist,
			ok:     true,
		},
		{
			name: "OpError os.SyscallError EEXIST",
			err: &netlink.OpError{
				Op:  "receive",
				Err: os.NewSyscallError("recvmsg", unix.EEXIST),
			},
			target: os.ErrExist,
			ok:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errors.Is(tt.err, tt.target)
			if diff := cmp.Diff(tt.ok, got); diff != "" {
				t.Fatalf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIntegrationEthtoolExtendedAcknowledge(t *testing.T) {
	t.Parallel()

	// The ethtool package uses extended acknowledgements and should populate
	// all of netlink.OpError's fields when unwrapped.
	c, err := ethtool.New()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skip("skipping, ethtool genetlink not available on this system")
		}

		t.Fatalf("failed to open ethtool genetlink: %v", err)
	}

	_, err = c.LinkInfo(ethtool.Interface{Name: "notexist0"})
	if err == nil {
		t.Fatal("expected an error, but none occurred")
	}

	var oerr *netlink.OpError
	if !errors.As(err, &oerr) {
		t.Fatalf("expected wrapped *netlink.OpError, but got: %T", err)
	}

	// Assume the message contents will be relatively static but don't hardcode
	// offset just in case things change.
	if oerr.Offset == 0 {
		t.Fatal("no offset specified in *netlink.OpError")
	}
	oerr.Offset = 0

	want := &netlink.OpError{
		Op:      "receive",
		Err:     unix.ENODEV,
		Message: "no device matches name",
	}

	if diff := cmp.Diff(want, oerr); diff != "" {
		t.Fatalf("unexpected *netlink.OpError (-want +got):\n%s", diff)
	}
}

func TestIntegrationConnClosedConn(t *testing.T) {
	t.Parallel()

	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial netlink: %v", err)
	}

	// Close the connection immediately and ensure that future calls get EBADF.
	if err := c.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "receive",
			fn: func() error {
				_, err := c.Receive()
				return err
			},
		},
		{
			name: "send",
			fn: func() error {
				_, err := c.Send(netlink.Message{})
				return err
			},
		},
		{
			name: "set option",
			fn: func() error {
				return c.SetOption(netlink.ExtendedAcknowledge, true)
			},
		},
		{
			name: "syscall conn",
			fn: func() error {
				_, err := c.SyscallConn()
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(unix.EBADF, tt.fn(), cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
		})
	}
}
