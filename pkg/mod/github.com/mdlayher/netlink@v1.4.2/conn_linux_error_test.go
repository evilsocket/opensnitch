//go:build linux
// +build linux

package netlink_test

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/josharian/native"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func TestConnReceiveErrorLinux(t *testing.T) {
	skipBigEndian(t)

	// Note: using *Conn instead of Linux-only *conn, to test
	// error handling logic in *Conn.Receive.
	//
	// This test also verifies the contractual behavior of OpError wrapping
	// errors from system calls in os.SyscallError, but NOT wrapping netlink
	// error codes.

	tests := []struct {
		name string
		msgs []netlink.Message
		in   error
		want error
	}{
		{
			name: "netlink message ENOENT",
			msgs: []netlink.Message{{
				Header: netlink.Header{
					Length:   20,
					Type:     netlink.Error,
					Sequence: 1,
					PID:      1,
				},
				// -2, little endian (ENOENT)
				Data: []byte{0xfe, 0xff, 0xff, 0xff},
			}},
			want: &netlink.OpError{
				Op:  "receive",
				Err: unix.ENOENT,
			},
		},
		{
			name: "syscall error ENOENT",
			in:   unix.ENOENT,
			want: &netlink.OpError{
				Op:  "receive",
				Err: os.NewSyscallError("recvmsg", unix.ENOENT),
			},
		},
		{
			name: "multipart done without error",
			msgs: []netlink.Message{
				{
					Header: netlink.Header{
						Flags: netlink.Multi,
					},
				},
				{
					Header: netlink.Header{
						Type:  netlink.Done,
						Flags: netlink.Multi,
					},
				},
			},
		},
		{
			name: "multipart done with error",
			msgs: []netlink.Message{
				{
					Header: netlink.Header{
						Flags: netlink.Multi,
					},
				},
				{
					Header: netlink.Header{
						Type:  netlink.Done,
						Flags: netlink.Multi,
					},
					// -2, little endian (ENOENT)
					Data: []byte{0xfe, 0xff, 0xff, 0xff},
				},
			},
			want: &netlink.OpError{
				Op:  "receive",
				Err: unix.ENOENT,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
				return tt.msgs, tt.in
			})
			defer c.Close()

			// Need to prepopulate nltest's internal buffers by invoking the
			// function once.
			_, _ = c.Send(netlink.Message{})

			_, got := c.Receive()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
		})
	}
}

func skipBigEndian(t *testing.T) {
	if binary.ByteOrder(native.Endian) == binary.BigEndian {
		t.Skip("skipping test on big-endian system")
	}
}
