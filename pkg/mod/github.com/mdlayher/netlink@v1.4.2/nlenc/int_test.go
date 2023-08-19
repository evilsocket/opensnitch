package nlenc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestUintPanic(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		fn   func(b []byte)
	}{
		{
			name: "short put 8",
			b:    make([]byte, 0),
			fn: func(b []byte) {
				PutUint8(b, 0)
			},
		},
		{
			name: "long put 8",
			b:    make([]byte, 2),
			fn: func(b []byte) {
				PutUint8(b, 0)
			},
		},
		{
			name: "short get 8",
			b:    make([]byte, 0),
			fn: func(b []byte) {
				Uint8(b)
			},
		},
		{
			name: "long get 8",
			b:    make([]byte, 2),
			fn: func(b []byte) {
				Uint8(b)
			},
		},
		{
			name: "short put 16",
			b:    make([]byte, 1),
			fn: func(b []byte) {
				PutUint16(b, 0)
			},
		},
		{
			name: "long put 16",
			b:    make([]byte, 3),
			fn: func(b []byte) {
				PutUint16(b, 0)
			},
		},
		{
			name: "short get 16",
			b:    make([]byte, 1),
			fn: func(b []byte) {
				Uint16(b)
			},
		},
		{
			name: "long get 16",
			b:    make([]byte, 3),
			fn: func(b []byte) {
				Uint16(b)
			},
		},
		{
			name: "short put 32",
			b:    make([]byte, 3),
			fn: func(b []byte) {
				PutUint32(b, 0)
			},
		},
		{
			name: "long put 32",
			b:    make([]byte, 5),
			fn: func(b []byte) {
				PutUint32(b, 0)
			},
		},
		{
			name: "short get 32",
			b:    make([]byte, 3),
			fn: func(b []byte) {
				Uint32(b)
			},
		},
		{
			name: "long get 32",
			b:    make([]byte, 5),
			fn: func(b []byte) {
				Uint32(b)
			},
		},
		{
			name: "short put 64",
			b:    make([]byte, 7),
			fn: func(b []byte) {
				PutUint64(b, 0)
			},
		},
		{
			name: "long put 64",
			b:    make([]byte, 9),
			fn: func(b []byte) {
				PutUint64(b, 0)
			},
		},
		{
			name: "short get 64",
			b:    make([]byte, 7),
			fn: func(b []byte) {
				Uint64(b)
			},
		},
		{
			name: "long get 64",
			b:    make([]byte, 9),
			fn: func(b []byte) {
				Uint64(b)
			},
		},
		{
			name: "short put signed 32",
			b:    make([]byte, 3),
			fn: func(b []byte) {
				PutInt32(b, 0)
			},
		},
		{
			name: "short get signed 32",
			b:    make([]byte, 3),
			fn: func(b []byte) {
				Int32(b)
			},
		},
		{
			name: "long put signed 32",
			b:    make([]byte, 5),
			fn: func(b []byte) {
				PutInt32(b, 0)
			},
		},
		{
			name: "long get signed 32",
			b:    make([]byte, 5),
			fn: func(b []byte) {
				Int32(b)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected panic, but none occurred")
				}
			}()

			tt.fn(tt.b)
			t.Fatal("reached end of test case without panic")
		})
	}
}

func TestUint8(t *testing.T) {
	tests := []struct {
		v uint8
		b []byte
	}{
		{
			v: 0x01,
			b: []byte{0x01},
		},
		{
			v: 0xff,
			b: []byte{0xff},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("0x%03x", tt.v), func(t *testing.T) {
			b := make([]byte, 1)
			PutUint8(b, tt.v)

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}

			v := Uint8(b)

			if want, got := tt.v, v; want != got {
				t.Fatalf("unexpected integer:\n- want: 0x%03x\n-  got: 0x%03x",
					want, got)
			}

			b = Uint8Bytes(tt.v)

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}
		})
	}
}

func TestUint16(t *testing.T) {
	skipBigEndian(t)
	tests := []struct {
		v uint16
		b []byte
	}{
		{
			v: 0x1,
			b: []byte{0x01, 0x00},
		},
		{
			v: 0x0102,
			b: []byte{0x02, 0x01},
		},
		{
			v: 0x1234,
			b: []byte{0x34, 0x12},
		},
		{
			v: 0xffff,
			b: []byte{0xff, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("0x%04x", tt.v), func(t *testing.T) {
			b := make([]byte, 2)
			PutUint16(b, tt.v)

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}

			v := Uint16(b)

			if want, got := tt.v, v; want != got {
				t.Fatalf("unexpected integer:\n- want: 0x%04x\n-  got: 0x%04x",
					want, got)
			}

			b = Uint16Bytes(tt.v)

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}
		})
	}
}

func TestUint32(t *testing.T) {
	skipBigEndian(t)
	tests := []struct {
		v uint32
		b []byte
	}{
		{
			v: 0x1,
			b: []byte{0x01, 0x00, 0x00, 0x00},
		},
		{
			v: 0x0102,
			b: []byte{0x02, 0x01, 0x00, 0x00},
		},
		{
			v: 0x1234,
			b: []byte{0x34, 0x12, 0x00, 0x00},
		},
		{
			v: 0xffff,
			b: []byte{0xff, 0xff, 0x00, 0x00},
		},
		{
			v: 0x01020304,
			b: []byte{0x04, 0x03, 0x02, 0x01},
		},
		{
			v: 0x1a2a3a4a,
			b: []byte{0x4a, 0x3a, 0x2a, 0x1a},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("0x%08x", tt.v), func(t *testing.T) {
			b := make([]byte, 4)
			PutUint32(b, tt.v)

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}

			v := Uint32(b)

			if want, got := tt.v, v; want != got {
				t.Fatalf("unexpected integer:\n- want: 0x%04x\n-  got: 0x%04x",
					want, got)
			}

			b = Uint32Bytes(tt.v)

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}
		})
	}
}

func TestUint64(t *testing.T) {
	skipBigEndian(t)
	tests := []struct {
		v uint64
		b []byte
	}{
		{
			v: 0x1,
			b: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			v: 0x0102,
			b: []byte{0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			v: 0x1234,
			b: []byte{0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			v: 0xffff,
			b: []byte{0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			v: 0x01020304,
			b: []byte{0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00},
		},
		{
			v: 0x1a2a3a4a,
			b: []byte{0x4a, 0x3a, 0x2a, 0x1a, 0x00, 0x00, 0x00, 0x00},
		},
		{
			v: 0x0102030405060708,
			b: []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
		},
		{
			v: 0x1a2a3a4a5a6a7a8a,
			b: []byte{0x8a, 0x7a, 0x6a, 0x5a, 0x4a, 0x3a, 0x2a, 0x1a},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("0x%016x", tt.v), func(t *testing.T) {
			b := make([]byte, 8)
			PutUint64(b, tt.v)

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}

			v := Uint64(b)

			if want, got := tt.v, v; want != got {
				t.Fatalf("unexpected integer:\n- want: 0x%04x\n-  got: 0x%04x",
					want, got)
			}

			b = Uint64Bytes(tt.v)

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}
		})
	}
}

func TestInt32(t *testing.T) {
	skipBigEndian(t)
	tests := []struct {
		v int32
		b []byte
	}{
		{
			v: 0x1,
			b: []byte{0x01, 0x00, 0x00, 0x00},
		},
		{
			v: 0x0102,
			b: []byte{0x02, 0x01, 0x00, 0x00},
		},
		{
			v: 0x1234,
			b: []byte{0x34, 0x12, 0x00, 0x00},
		},
		{
			v: 0xffff,
			b: []byte{0xff, 0xff, 0x00, 0x00},
		},
		{
			v: 0x01020304,
			b: []byte{0x04, 0x03, 0x02, 0x01},
		},
		{
			v: 0x1a2a3a4a,
			b: []byte{0x4a, 0x3a, 0x2a, 0x1a},
		},
		{
			v: -1,
			b: []byte{0xff, 0xff, 0xff, 0xff},
		},
		{
			v: -2,
			b: []byte{0xfe, 0xff, 0xff, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("0x%08x", tt.v), func(t *testing.T) {
			b := make([]byte, 4)
			PutInt32(b, tt.v)

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}

			v := Int32(b)

			if want, got := tt.v, v; want != got {
				t.Fatalf("unexpected integer:\n- want: 0x%04x\n-  got: 0x%04x",
					want, got)
			}

			b = Int32Bytes(tt.v)

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}
		})
	}
}

func skipBigEndian(t *testing.T) {
	if NativeEndian() == binary.BigEndian {
		t.Skip("skipping test on big-endian system")
	}
}
