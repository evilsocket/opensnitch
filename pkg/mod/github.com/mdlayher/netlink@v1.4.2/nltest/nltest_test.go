package nltest_test

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
)

func TestConnSend(t *testing.T) {
	req := netlink.Message{
		Data: []byte{0xff, 0xff, 0xff, 0xff},
	}

	c := nltest.Dial(func(creq []netlink.Message) ([]netlink.Message, error) {
		if got, want := len(creq), 1; got != want {
			t.Fatalf("unexpected number of messages: got %d, want %d", got, want)
		}
		if want, got := req.Data, creq[0].Data; !bytes.Equal(want, got) {
			t.Fatalf("unexpected request data:\n- want: %v\n-  got: %v",
				want, got)
		}

		return nil, nil
	})
	defer c.Close()

	if _, err := c.Send(req); err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
}

func TestConnReceiveMulticast(t *testing.T) {
	msgs := []netlink.Message{{
		Data: []byte{0xff, 0xff, 0xff, 0xff},
	}}

	c := nltest.Dial(func(zero []netlink.Message) ([]netlink.Message, error) {
		if zero == nil {
			return msgs, nil
		}

		if want, got := (netlink.Message{}), zero; !reflect.DeepEqual(want, got) {
			t.Fatalf("unexpected zero message:\n- want: %v\n-  got: %v",
				want, got)
		}

		return msgs, nil
	})
	defer c.Close()

	got, err := c.Receive()
	if err != nil {
		t.Fatalf("failed to receive messages: %v", err)
	}

	if want := msgs; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected multicast messages:\n- want: %v\n-  got: %v",
			want, got)
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

func TestConnReceiveError(t *testing.T) {
	errFoo := errors.New("foo")

	c := nltest.Dial(func(_ []netlink.Message) ([]netlink.Message, error) {
		return nil, errFoo
	})
	defer c.Close()

	want := &netlink.OpError{
		Op:  "receive",
		Err: errFoo,
	}

	_, err := c.Receive()
	if diff := cmp.Diff(want.Error(), err.Error()); diff != "" {
		t.Fatalf("unexpected error (-want +got):\n%s", diff)
	}
}

func TestConnExecuteOK(t *testing.T) {
	req := netlink.Message{
		Header: netlink.Header{
			Length:   16,
			Flags:    netlink.Request,
			Sequence: 1,
			PID:      1,
		},
	}

	c := nltest.Dial(func(creq []netlink.Message) ([]netlink.Message, error) {
		// Turn the request back around to the client.
		return creq, nil
	})
	defer c.Close()

	got, err := c.Execute(req)
	if err != nil {
		t.Fatalf("failed to execute request: %v", err)
	}

	if want := []netlink.Message{req}; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected response messages:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestConnExecuteMultipartOK(t *testing.T) {
	req := netlink.Message{
		Header: netlink.Header{
			Length:   16,
			Flags:    netlink.Request,
			Sequence: 1,
			PID:      1,
		},
	}

	c := nltest.Dial(func(creq []netlink.Message) ([]netlink.Message, error) {
		// Client should only receive one message with multipart flag set.
		// TODO: append(creq, creq)?
		creqs := make([]netlink.Message, 2*len(creq))
		copy(creqs, creq)
		copy(creqs[len(creq):], creq)
		return nltest.Multipart(creqs)
	})
	defer c.Close()

	got, err := c.Execute(req)
	if err != nil {
		t.Fatalf("failed to execute request: %v", err)
	}

	req.Header.Flags |= netlink.Multi
	if want := []netlink.Message{req}; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected response messages:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestConnExecuteError(t *testing.T) {
	err := errors.New("foo")

	c := nltest.Dial(func(creq []netlink.Message) ([]netlink.Message, error) {
		// Error should be surfaced by Execute's call to Receive.
		return nil, err
	})
	defer c.Close()

	want := &netlink.OpError{
		Op:  "receive",
		Err: err,
	}

	_, got := c.Execute(netlink.Message{})
	if diff := cmp.Diff(want.Error(), got.Error()); diff != "" {
		t.Fatalf("unexpected error (-want +got):\n%s", diff)
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

func TestError(t *testing.T) {
	const (
		eperm  = 1
		enoent = 2
	)

	tests := []struct {
		name   string
		number int
		in     []netlink.Message
		out    []netlink.Message
	}{
		{
			name:   "EPERM",
			number: eperm,
			in: []netlink.Message{
				{
					Header: netlink.Header{
						Length:   24,
						Flags:    netlink.Request | netlink.Dump,
						Sequence: 10,
						PID:      1000,
					},
					Data: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
				},
			},
			out: []netlink.Message{{
				Header: netlink.Header{
					Length:   28,
					Type:     netlink.Error,
					Flags:    netlink.Request | netlink.Dump,
					Sequence: 10,
					PID:      1000,
				},
				Data: []byte{
					0xff, 0xff, 0xff, 0xff,
					0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				},
			}},
		},
		{
			name:   "ENOENT",
			number: enoent,
			in: []netlink.Message{
				{
					Header: netlink.Header{
						Length:   20,
						Flags:    netlink.Request,
						Sequence: 1,
						PID:      100,
					},
					Data: []byte{0x11, 0x22, 0x33, 0x44},
				},
			},
			out: []netlink.Message{{
				Header: netlink.Header{
					Length:   24,
					Type:     netlink.Error,
					Flags:    netlink.Request,
					Sequence: 1,
					PID:      100,
				},
				Data: []byte{
					0xfe, 0xff, 0xff, 0xff,
					0x11, 0x22, 0x33, 0x44,
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := nltest.Error(tt.number, tt.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if want, got := tt.out, out; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected output messages:\n- want: %v\n-  got: %v",
					want, got)
			}
		})
	}
}

func TestMultipart(t *testing.T) {
	tests := []struct {
		name string
		in   []netlink.Message
		out  []netlink.Message
	}{
		{
			name: "no messages",
		},
		{
			name: "one message, no changes",
			in: []netlink.Message{{
				Header: netlink.Header{
					Length: 20,
				},
				Data: []byte{0xff, 0xff, 0xff, 0xff},
			}},
			out: []netlink.Message{{
				Header: netlink.Header{
					Length: 20,
				},
				Data: []byte{0xff, 0xff, 0xff, 0xff},
			}},
		},
		{
			name: "two messages, multipart",
			in: []netlink.Message{
				{
					Header: netlink.Header{
						Length: 20,
					},
					Data: []byte{0xff, 0xff, 0xff, 0xff},
				},
				{
					Header: netlink.Header{
						Length: 16,
					},
				},
			},
			out: []netlink.Message{
				{
					Header: netlink.Header{
						Length: 20,
						Flags:  netlink.Multi,
					},
					Data: []byte{0xff, 0xff, 0xff, 0xff},
				},
				{
					Header: netlink.Header{
						Length: 16,
						Type:   netlink.Done,
						Flags:  netlink.Multi,
					},
				},
			},
		},
		{
			name: "three messages, multipart",
			in: []netlink.Message{
				{
					Header: netlink.Header{
						Length: 20,
					},
					Data: []byte{0xff, 0xff, 0xff, 0xff},
				},
				{
					Header: netlink.Header{
						Length: 24,
					},
					Data: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				},
				{
					Header: netlink.Header{
						Length: 16,
					},
				},
			},
			out: []netlink.Message{
				{
					Header: netlink.Header{
						Length: 20,
						Flags:  netlink.Multi,
					},
					Data: []byte{0xff, 0xff, 0xff, 0xff},
				},
				{
					Header: netlink.Header{
						Length: 24,
						Flags:  netlink.Multi,
					},
					Data: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				},
				{
					Header: netlink.Header{
						Length: 16,
						Type:   netlink.Done,
						Flags:  netlink.Multi,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := nltest.Multipart(tt.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if want, got := tt.out, out; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected output messages:\n- want: %v\n-  got: %v",
					want, got)
			}
		})
	}
}

func TestCheckRequestPanic(t *testing.T) {
	tests := []struct {
		name  string
		types []netlink.HeaderType
		flags []netlink.HeaderFlags
		reqs  []netlink.Message
	}{
		{
			name:  "types",
			types: []netlink.HeaderType{0},
		},
		{
			name:  "flags",
			flags: []netlink.HeaderFlags{0},
		},
		{
			name:  "requests",
			types: []netlink.HeaderType{0},
			flags: []netlink.HeaderFlags{0},
			reqs:  []netlink.Message{{}, {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected a panic, but none occurred")
				}
			}()

			fn := nltest.CheckRequest(tt.types, tt.flags, noop)
			fn(tt.reqs)
		})
	}
}

func TestCheckRequest(t *testing.T) {
	tests := []struct {
		name  string
		types []netlink.HeaderType
		flags []netlink.HeaderFlags
		reqs  []netlink.Message
		ok    bool
	}{
		{
			name:  "no checking",
			types: []netlink.HeaderType{0},
			flags: []netlink.HeaderFlags{0},
			reqs:  []netlink.Message{{}},
			ok:    true,
		},
		{
			name:  "type only",
			types: []netlink.HeaderType{10},
			flags: []netlink.HeaderFlags{0},
			reqs: []netlink.Message{{
				Header: netlink.Header{
					Type:  10,
					Flags: netlink.Request,
				},
			}},
			ok: true,
		},
		{
			name:  "flags only",
			types: []netlink.HeaderType{0},
			flags: []netlink.HeaderFlags{netlink.Request},
			reqs: []netlink.Message{{
				Header: netlink.Header{
					Type:  10,
					Flags: netlink.Request,
				},
			}},
			ok: true,
		},
		{
			name:  "bad type",
			types: []netlink.HeaderType{10, 20},
			flags: []netlink.HeaderFlags{netlink.Request, netlink.Replace},
			reqs: []netlink.Message{
				{
					Header: netlink.Header{
						Type:  10,
						Flags: netlink.Request,
					},
				},
				{
					Header: netlink.Header{
						Type:  99,
						Flags: netlink.Replace,
					},
				},
			},
		},
		{
			name:  "bad flags",
			types: []netlink.HeaderType{10, 20},
			flags: []netlink.HeaderFlags{netlink.Request, netlink.Replace},
			reqs: []netlink.Message{
				{
					Header: netlink.Header{
						Type:  10,
						Flags: netlink.Request,
					},
				},
				{
					Header: netlink.Header{
						Type:  20,
						Flags: netlink.Request,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := nltest.CheckRequest(tt.types, tt.flags, noop)
			_, err := fn(tt.reqs)

			if err != nil && tt.ok {
				t.Fatalf("unexpected error: %v", err)
			}
			if err == nil && !tt.ok {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

var noop = func(req []netlink.Message) ([]netlink.Message, error) {
	return nil, nil
}
