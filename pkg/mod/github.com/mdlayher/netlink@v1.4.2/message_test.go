package netlink

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/josharian/native"
)

func TestHeaderFlagsString(t *testing.T) {
	tests := []struct {
		f HeaderFlags
		s string
	}{
		{
			f: 0,
			s: "0",
		},
		{
			f: Request,
			s: "request",
		},
		{
			f: Multi,
			s: "multi",
		},
		{
			f: Echo,
			s: "echo",
		},
		{
			f: DumpInterrupted,
			s: "dumpinterrupted",
		},
		{
			f: DumpFiltered,
			s: "dumpfiltered",
		},
		{
			f: Root,
			s: "0x100",
		},
		{
			f: Replace,
			s: "0x100",
		},
		{
			f: Match,
			s: "0x200",
		},
		{
			f: Excl,
			s: "0x200",
		},
		{
			f: Atomic,
			s: "0x400",
		},
		{
			f: Create,
			s: "0x400",
		},
		{
			f: Append,
			s: "0x800",
		},
		{
			f: Dump,
			s: "0x300",
		},
		{
			f: Request | Dump,
			s: "request|0x300",
		},
		{
			f: Request | Acknowledge | Create | Replace,
			s: "request|acknowledge|0x500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if want, got := tt.s, tt.f.String(); want != got {
				t.Fatalf("unexpected flag string for: %016b\n- want: %q\n-  got: %q",
					tt.f, want, got)
			}
		})
	}
}

func TestHeaderTypeString(t *testing.T) {
	tests := []struct {
		t HeaderType
		s string
	}{
		{
			t: 0,
			s: "unknown(0)",
		},
		{
			t: Noop,
			s: "noop",
		},
		{
			t: Error,
			s: "error",
		},
		{
			t: Done,
			s: "done",
		},
		{
			t: Overrun,
			s: "overrun",
		},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if want, got := tt.s, tt.t.String(); want != got {
				t.Fatalf("unexpected header type string:\n- want: %q\n-  got: %q",
					want, got)
			}
		})
	}
}

func TestMessageMarshal(t *testing.T) {
	skipBigEndian(t)

	tests := []struct {
		name string
		m    Message
		b    []byte
		err  error
	}{
		{
			name: "empty",
			m:    Message{},
			err:  errIncorrectMessageLength,
		},
		{
			name: "short",
			m: Message{
				Header: Header{
					Length: 15,
				},
			},
			err: errIncorrectMessageLength,
		},
		{
			name: "unaligned",
			m: Message{
				Header: Header{
					Length: 17,
				},
			},
			err: errIncorrectMessageLength,
		},
		{
			name: "OK no data",
			m: Message{
				Header: Header{
					Length: 16,
				},
			},
			b: []byte{
				0x10, 0x00, 0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "OK unaligned data",
			m: Message{
				Header: Header{
					Length:   20,
					Flags:    Request,
					Sequence: 1,
					PID:      10,
				},
				Data: []byte("abc"),
			},
			b: []byte{
				0x14, 0x00, 0x00, 0x00,
				0x00, 0x00,
				0x01, 0x00,
				0x01, 0x00, 0x00, 0x00,
				0x0a, 0x00, 0x00, 0x00,
				0x61, 0x62, 0x63, 0x00, /* last byte padded */
			},
		},
		{
			name: "OK aligned data",
			m: Message{
				Header: Header{
					Length:   20,
					Type:     Error,
					Sequence: 2,
					PID:      20,
				},
				Data: []byte("abcd"),
			},
			b: []byte{
				0x14, 0x00, 0x00, 0x00,
				0x02, 0x00,
				0x00, 0x00,
				0x02, 0x00, 0x00, 0x00,
				0x14, 0x00, 0x00, 0x00,
				0x61, 0x62, 0x63, 0x64,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.m.MarshalBinary()

			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}
			if err != nil {
				return
			}

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected Message bytes:\n- want: [%# x]\n-  got: [%# x]", want, got)
			}
		})
	}
}

func TestMessageUnmarshal(t *testing.T) {
	skipBigEndian(t)

	tests := []struct {
		name string
		b    []byte
		m    Message
		err  error
	}{
		{
			name: "empty",
			err:  errShortMessage,
		},
		{
			name: "short",
			b:    make([]byte, 15),
			err:  errShortMessage,
		},
		{
			name: "unaligned",
			b:    make([]byte, 17),
			err:  errUnalignedMessage,
		},
		{
			name: "fuzz crasher: length shorter than slice",
			b:    []byte("\x1d000000000000000"),
			err:  errShortMessage,
		},
		{
			name: "fuzz crasher: length longer than slice",
			b:    []byte("\x13\x00\x00\x000000000000000000"),
			err:  errShortMessage,
		},
		{
			name: "OK no data",
			b: []byte{
				0x10, 0x00, 0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
			m: Message{
				Header: Header{
					Length: 16,
				},
				Data: make([]byte, 0),
			},
		},
		{
			name: "OK data",
			m: Message{
				Header: Header{
					Length:   20,
					Type:     Error,
					Sequence: 2,
					PID:      20,
				},
				Data: []byte("abcd"),
			},
			b: []byte{
				0x14, 0x00, 0x00, 0x00,
				0x02, 0x00,
				0x00, 0x00,
				0x02, 0x00, 0x00, 0x00,
				0x14, 0x00, 0x00, 0x00,
				0x61, 0x62, 0x63, 0x64,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m Message
			err := (&m).UnmarshalBinary(tt.b)

			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}
			if err != nil {
				return
			}

			if want, got := tt.m, m; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected Message:\n- want: %#v\n-  got: %#v", want, got)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		req  Message
		rep  []Message
		err  error
	}{
		{
			name: "mismatched sequence",
			req: Message{
				Header: Header{
					Sequence: 1,
				},
			},
			rep: []Message{{
				Header: Header{
					Sequence: 2,
				},
			}},
			err: errMismatchedSequence,
		},
		{
			name: "mismatched sequence second message",
			req: Message{
				Header: Header{
					Sequence: 1,
				},
			},
			rep: []Message{
				{
					Header: Header{
						Sequence: 1,
					},
				},
				{
					Header: Header{
						Sequence: 2,
					},
				},
			},
			err: errMismatchedSequence,
		},
		{
			name: "mismatched PID",
			req: Message{
				Header: Header{
					PID: 1,
				},
			},
			rep: []Message{{
				Header: Header{
					PID: 2,
				},
			}},
			err: errMismatchedPID,
		},
		{
			name: "mismatched PID second message",
			req: Message{
				Header: Header{
					PID: 1,
				},
			},
			rep: []Message{
				{
					Header: Header{
						PID: 1,
					},
				},
				{
					Header: Header{
						PID: 2,
					},
				},
			},
			err: errMismatchedPID,
		},
		{
			name: "OK matching sequence and PID",
			req: Message{
				Header: Header{
					Sequence: 1,
					PID:      1,
				},
			},
			rep: []Message{{
				Header: Header{
					Sequence: 1,
					PID:      1,
				},
			}},
		},
		{
			name: "OK multicast messages",
			// No request
			req: Message{},
			rep: []Message{{
				Header: Header{
					Sequence: 1,
					PID:      0,
				},
			}},
		},
		{
			name: "OK no PID assigned yet",
			// No request
			req: Message{
				Header: Header{
					Sequence: 1,
					PID:      0,
				},
			},
			rep: []Message{{
				Header: Header{
					Sequence: 1,
					PID:      9999,
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.req, tt.rep)
			if err == nil {
				if tt.err != nil {
					t.Fatal("expected an error, but none occurred")
				}

				return
			}

			oerr, ok := err.(*OpError)
			if !ok {
				t.Fatalf("unexpected validate error type: %#v", err)
			}

			if want, got := "validate", oerr.Op; want != got {
				t.Fatalf("unexpected op:\n- want: %v\n-  got: %v",
					want, got)
			}

			if want, got := tt.err, oerr.Err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
					want, got)
			}
		})
	}
}

func skipBigEndian(t *testing.T) {
	if binary.ByteOrder(native.Endian) == binary.BigEndian {
		t.Skip("skipping test on big-endian system")
	}
}
