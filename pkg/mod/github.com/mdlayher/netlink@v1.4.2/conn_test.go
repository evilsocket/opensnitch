package netlink_test

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
)

func TestConnExecute(t *testing.T) {
	req := netlink.Message{
		Header: netlink.Header{
			Flags:    netlink.Request | netlink.Acknowledge,
			Sequence: 1,
		},
	}

	replies := []netlink.Message{{
		Header: netlink.Header{
			Type:     netlink.Error,
			Sequence: 1,
			PID:      1,
		},
		// Error code "success", no need to echo request back in this test
		Data: make([]byte, 4),
	}}

	c := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
		return replies, nil
	})
	defer c.Close()

	msgs, err := c.Execute(req)
	if err != nil {
		t.Fatalf("failed to execute: %v", err)
	}

	// Fill in fields for comparison
	req.Header.Length = 16

	if want, got := replies, msgs; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected replies:\n- want: %#v\n-  got: %#v",
			want, got)
	}
}

func TestConnSend(t *testing.T) {
	c := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
		return nil, errors.New("should not be received")
	})
	defer c.Close()

	// Let Conn.Send populate length, sequence, PID
	m := netlink.Message{}

	out, err := c.Send(m)
	if err != nil {
		t.Fatalf("failed to send message: %v", err)
	}

	// Make the same changes that Conn.Send should
	m = netlink.Message{
		Header: netlink.Header{
			Length:   16,
			Sequence: out.Header.Sequence,
			PID:      1,
		},
	}

	if want, got := m, out; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected output message from Conn.Send:\n- want: %#v\n-  got: %#v",
			want, got)
	}

	// Keep sending to verify sequence number increment
	seq := m.Header.Sequence
	for i := 0; i < 100; i++ {
		out, err := c.Send(netlink.Message{})
		if err != nil {
			t.Fatalf("failed to send message: %v", err)
		}

		seq++
		if want, got := seq, out.Header.Sequence; want != got {
			t.Fatalf("unexpected sequence number:\n- want: %v\n-  got: %v",
				want, got)
		}
	}
}

func TestConnExecuteMultipart(t *testing.T) {
	msg := netlink.Message{
		Header: netlink.Header{
			Sequence: 1,
		},
		Data: []byte{0xff, 0xff, 0xff, 0xff},
	}

	c := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
		return nltest.Multipart([]netlink.Message{
			msg,
			// Will be filled with multipart done information.
			{},
		})
	})
	defer c.Close()

	msgs, err := c.Execute(msg)
	if err != nil {
		t.Fatalf("failed to receive messages: %v", err)
	}

	msg.Header.Flags |= netlink.Multi

	if want, got := []netlink.Message{msg}, msgs; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected output messages from Conn.Receive:\n- want: %#v\n-  got: %#v",
			want, got)
	}
}

func TestConnExecuteNoMessages(t *testing.T) {
	c := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
		return nil, io.EOF
	})
	defer c.Close()

	msgs, err := c.Execute(netlink.Message{})
	if err != nil {
		t.Fatalf("failed to execute: %v", err)
	}

	if l := len(msgs); l > 0 {
		t.Fatalf("expected no messages, but got: %d", l)
	}
}

func TestConnReceiveNoMessages(t *testing.T) {
	c := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
		return nil, io.EOF
	})
	defer c.Close()

	msgs, err := c.Receive()
	if err != nil {
		t.Fatalf("failed to execute: %v", err)
	}

	if l := len(msgs); l > 0 {
		t.Fatalf("expected no messages, but got: %d", l)
	}
}

func TestConnReceiveShortErrorNumber(t *testing.T) {
	c := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
		return []netlink.Message{{
			Header: netlink.Header{
				Length: 20,
				Type:   netlink.Error,
			},
			Data: []byte{0x01},
		}}, nil
	})
	defer c.Close()

	_, err := c.Receive()
	if !strings.Contains(err.Error(), "not enough data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnReceiveShortErrorAcknowledgementHeader(t *testing.T) {
	c := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
		return []netlink.Message{{
			Header: netlink.Header{
				Length: 20,
				Type:   netlink.Error,
				Flags:  netlink.AcknowledgeTLVs,
			},
			Data: []byte{
				// errno.
				0x01, 0x00, 0x00, 0x00,
				// nlmsghdr
				0xff,
			},
		}}, nil
	})
	defer c.Close()

	_, err := c.Receive()
	if !strings.Contains(err.Error(), "not enough data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnJoinLeaveGroupUnsupported(t *testing.T) {
	c := nltest.Dial(nil)
	defer c.Close()

	ops := []func(group uint32) error{
		c.JoinGroup,
		c.LeaveGroup,
	}

	for _, op := range ops {
		err := op(0)
		if !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

func TestConnSetBPFUnsupported(t *testing.T) {
	c := nltest.Dial(nil)
	defer c.Close()

	err := c.SetBPF(nil)
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnSetDeadlineUnsupported(t *testing.T) {
	c := nltest.Dial(nil)
	defer c.Close()

	err := c.SetDeadline(time.Now())
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnSetOptionUnsupported(t *testing.T) {
	c := nltest.Dial(nil)
	defer c.Close()

	err := c.SetOption(0, false)
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnSetBuffersUnsupported(t *testing.T) {
	c := nltest.Dial(nil)
	defer c.Close()

	ops := []func(n int) error{
		c.SetReadBuffer,
		c.SetWriteBuffer,
	}

	for _, op := range ops {
		err := op(0)
		if !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

func TestConnSyscallConnUnsupported(t *testing.T) {
	c := nltest.Dial(nil)
	defer c.Close()

	if _, err := c.SyscallConn(); !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}
