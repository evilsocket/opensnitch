//go:build linux
// +build linux

package netlink

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

func TestHeaderMemoryLayoutLinux(t *testing.T) {
	var nh Header
	var sh syscall.NlMsghdr

	if want, got := unsafe.Sizeof(sh), unsafe.Sizeof(nh); want != got {
		t.Fatalf("unexpected structure sizes:\n- want: %v\n-  got: %v",
			want, got)
	}

	sh = syscall.NlMsghdr{
		Len:   0x10101010,
		Type:  0x2020,
		Flags: 0x3030,
		Seq:   0x40404040,
		Pid:   0x50505050,
	}
	nh = sysToHeader(sh)

	if want, got := sh.Len, nh.Length; want != got {
		t.Fatalf("unexpected header length:\n- want: %v\n-  got: %v",
			want, got)
	}
	if want, got := sh.Type, uint16(nh.Type); want != got {
		t.Fatalf("unexpected header type:\n- want: %v\n-  got: %v",
			want, got)
	}
	if want, got := sh.Flags, uint16(nh.Flags); want != got {
		t.Fatalf("unexpected header flags:\n- want: %v\n-  got: %v",
			want, got)
	}
	if want, got := sh.Seq, nh.Sequence; want != got {
		t.Fatalf("unexpected header sequence:\n- want: %v\n-  got: %v",
			want, got)
	}
	if want, got := sh.Pid, nh.PID; want != got {
		t.Fatalf("unexpected header PID:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func Test_checkMessageExtendedAcknowledgementTLVs(t *testing.T) {
	tests := []struct {
		name string
		m    Message
		err  *OpError
	}{
		{
			name: "error",
			m: Message{
				Header: Header{
					Type: Error,
					// Indicate the use of extended acknowledgement.
					Flags: AcknowledgeTLVs,
				},
				Data: packExtACK(
					-1,
					// The caller's request message with arbitrary bytes that we
					// skip over when parsing the TLVs.
					&Message{
						Header: Header{Length: 4},
						Data:   []byte{0xff, 0xff, 0xff, 0xff},
					},
					// The actual extended acknowledgement TLVs.
					[]Attribute{
						{
							Type: 1,
							Data: nlenc.Bytes("bad request"),
						},
						{
							Type: 2,
							Data: nlenc.Uint32Bytes(2),
						},
					},
				),
			},
			err: &OpError{
				Op:      "receive",
				Err:     unix.Errno(1),
				Message: "bad request",
				Offset:  2,
			},
		},
		{
			name: "done multi",
			m: Message{
				Header: Header{
					Type: Done,
					// Indicate the use of extended acknowledgement.
					Flags: Multi | AcknowledgeTLVs,
				},
				Data: packExtACK(
					-1,
					// No message, straight to TLVs.
					nil,
					[]Attribute{
						{
							Type: 1,
							Data: nlenc.Bytes("bad request"),
						},
						{
							Type: 2,
							Data: nlenc.Uint32Bytes(2),
						},
					},
				),
			},
			err: &OpError{
				Op:      "receive",
				Err:     unix.Errno(1),
				Message: "bad request",
				Offset:  2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.err, checkMessage(tt.m)); diff != "" {
				t.Fatalf("unexpected OpError (-want +got):\n%s", diff)
			}
		})
	}
}

// packExtACK packs an extended acknowledgement response.
func packExtACK(errno int32, m *Message, tlvs []Attribute) []byte {
	b := nlenc.Int32Bytes(errno)

	if m != nil {
		// Copy the header length logic from Conn.
		m.Header.Length = uint32(nlmsgAlign(nlmsgLength(len(m.Data))))
		mb, err := m.MarshalBinary()
		if err != nil {
			panicf("failed to marshal message: %v", err)
		}

		b = append(b, mb...)
	}

	ab, err := MarshalAttributes(tlvs)
	if err != nil {
		panicf("failed to marshal attributes: %v", err)
	}

	return append(b, ab...)
}
