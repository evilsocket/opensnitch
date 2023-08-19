package netlink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/josharian/native"
	"github.com/mdlayher/netlink/nlenc"
)

func TestMarshalAttributes(t *testing.T) {
	skipBigEndian(t)

	tests := []struct {
		name  string
		attrs []Attribute
		b     []byte
		err   error
	}{
		{
			name: "one attribute, short length",
			attrs: []Attribute{{
				Length: 3,
				Type:   1,
			}},
			err: errInvalidAttribute,
		},
		{
			name: "one attribute, no data",
			attrs: []Attribute{{
				Length: 4,
				Type:   1,
				Data:   make([]byte, 0),
			}},
			b: []byte{
				0x04, 0x00,
				0x01, 0x00,
			},
		},
		{
			name: "one attribute, no data, length calculated",
			attrs: []Attribute{{
				Type: 1,
				Data: make([]byte, 0),
			}},
			b: []byte{
				0x04, 0x00,
				0x01, 0x00,
			},
		},
		{
			name: "one attribute, padded",
			attrs: []Attribute{{
				Length: 5,
				Type:   1,
				Data:   []byte{0xff},
			}},
			b: []byte{
				0x05, 0x00,
				0x01, 0x00,
				0xff, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "one attribute, padded, length calculated",
			attrs: []Attribute{{
				Type: 1,
				Data: []byte{0xff},
			}},
			b: []byte{
				0x05, 0x00,
				0x01, 0x00,
				0xff, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "one attribute, aligned",
			attrs: []Attribute{{
				Length: 8,
				Type:   2,
				Data:   []byte{0xaa, 0xbb, 0xcc, 0xdd},
			}},
			b: []byte{
				0x08, 0x00,
				0x02, 0x00,
				0xaa, 0xbb, 0xcc, 0xdd,
			},
		},
		{
			name: "one attribute, aligned, length calculated",
			attrs: []Attribute{{
				Type: 2,
				Data: []byte{0xaa, 0xbb, 0xcc, 0xdd},
			}},
			b: []byte{
				0x08, 0x00,
				0x02, 0x00,
				0xaa, 0xbb, 0xcc, 0xdd,
			},
		},
		{
			name: "multiple attributes",
			attrs: []Attribute{
				{
					Length: 5,
					Type:   1,
					Data:   []byte{0xff},
				},
				{
					Length: 8,
					Type:   2,
					Data:   []byte{0xaa, 0xbb, 0xcc, 0xdd},
				},
				{
					Length: 4,
					Type:   3,
					Data:   make([]byte, 0),
				},
				{
					Length: 16,
					Type:   4,
					Data: []byte{
						0x11, 0x11, 0x11, 0x11,
						0x22, 0x22, 0x22, 0x22,
						0x33, 0x33, 0x33, 0x33,
					},
				},
			},
			b: []byte{
				// 1
				0x05, 0x00,
				0x01, 0x00,
				0xff, 0x00, 0x00, 0x00,
				// 2
				0x08, 0x00,
				0x02, 0x00,
				0xaa, 0xbb, 0xcc, 0xdd,
				// 3
				0x04, 0x00,
				0x03, 0x00,
				// 4
				0x10, 0x00,
				0x04, 0x00,
				0x11, 0x11, 0x11, 0x11,
				0x22, 0x22, 0x22, 0x22,
				0x33, 0x33, 0x33, 0x33,
			},
		},
		{
			name: "multiple attributes, length calculated",
			attrs: []Attribute{
				{
					Type: 1,
					Data: []byte{0xff},
				},
				{
					Type: 2,
					Data: []byte{0xaa, 0xbb, 0xcc, 0xdd},
				},
				{
					Type: 3,
					Data: make([]byte, 0),
				},
				{
					Type: 4,
					Data: []byte{
						0x11, 0x11, 0x11, 0x11,
						0x22, 0x22, 0x22, 0x22,
						0x33, 0x33, 0x33, 0x33,
					},
				},
			},
			b: []byte{
				// 1
				0x05, 0x00,
				0x01, 0x00,
				0xff, 0x00, 0x00, 0x00,
				// 2
				0x08, 0x00,
				0x02, 0x00,
				0xaa, 0xbb, 0xcc, 0xdd,
				// 3
				0x04, 0x00,
				0x03, 0x00,
				// 4
				0x10, 0x00,
				0x04, 0x00,
				0x11, 0x11, 0x11, 0x11,
				0x22, 0x22, 0x22, 0x22,
				0x33, 0x33, 0x33, 0x33,
			},
		},
		{
			name: "max type space, length 0",
			attrs: []Attribute{
				{
					Length: 4,
					Type:   0xffff,
					Data:   make([]byte, 0),
				},
			},
			b: []byte{
				0x04, 0x00,
				0xff, 0xff,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := MarshalAttributes(tt.attrs)

			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
					want, got)
			}
			if err != nil {
				return
			}

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}
		})
	}
}

func TestUnmarshalAttributes(t *testing.T) {
	skipBigEndian(t)

	tests := []struct {
		name  string
		b     []byte
		attrs []Attribute
		err   error
	}{
		{
			name: "empty slice",
		},
		{
			name: "short slice",
			b:    make([]byte, 3),
			err:  errInvalidAttribute,
		},
		{
			name: "length too short (<4 bytes)",
			b: []byte{
				0x03, 0x00,
				0x00,
			},
			err: errInvalidAttribute,
		},
		{
			name: "length too long",
			b: []byte{
				0xff, 0xff,
				0x00, 0x00,
			},
			err: errInvalidAttribute,
		},
		{
			name: "one attribute, not aligned",
			b: []byte{
				0x05, 0x00,
				0x01, 0x00,
				0xff,
			},
			attrs: []Attribute{{
				Length: 5,
				Type:   1,
				Data:   []byte{0xff},
			}},
		},
		{
			name: "fuzz crasher: length 1, too short",
			b:    []byte("\x01\x0000"),
			err:  errInvalidAttribute,
		},
		{
			name: "no attributes, length 0",
			b: []byte{
				0x00, 0x00,
				0x00, 0x00,
			},
		},
		{
			name: "one attribute, no data",
			b: []byte{
				0x04, 0x00,
				0x01, 0x00,
			},
			attrs: []Attribute{{
				Length: 4,
				Type:   1,
				Data:   make([]byte, 0),
			}},
		},
		{
			name: "one attribute, padded",
			b: []byte{
				0x05, 0x00,
				0x01, 0x00,
				0xff, 0x00, 0x00, 0x00,
			},
			attrs: []Attribute{{
				Length: 5,
				Type:   1,
				Data:   []byte{0xff},
			}},
		},
		{
			name: "one attribute, aligned",
			b: []byte{
				0x08, 0x00,
				0x02, 0x00,
				0xaa, 0xbb, 0xcc, 0xdd,
			},
			attrs: []Attribute{{
				Length: 8,
				Type:   2,
				Data:   []byte{0xaa, 0xbb, 0xcc, 0xdd},
			}},
		},
		{
			name: "multiple attributes",
			b: []byte{
				// 1
				0x05, 0x00,
				0x01, 0x00,
				0xff, 0x00, 0x00, 0x00,
				// 2
				0x08, 0x00,
				0x02, 0x00,
				0xaa, 0xbb, 0xcc, 0xdd,
				// 3
				0x04, 0x00,
				0x03, 0x00,
				// 4
				0x10, 0x00,
				0x04, 0x00,
				0x11, 0x11, 0x11, 0x11,
				0x22, 0x22, 0x22, 0x22,
				0x33, 0x33, 0x33, 0x33,
			},
			attrs: []Attribute{
				{
					Length: 5,
					Type:   1,
					Data:   []byte{0xff},
				},
				{
					Length: 8,
					Type:   2,
					Data:   []byte{0xaa, 0xbb, 0xcc, 0xdd},
				},
				{
					Length: 4,
					Type:   3,
					Data:   make([]byte, 0),
				},
				{
					Length: 16,
					Type:   4,
					Data: []byte{
						0x11, 0x11, 0x11, 0x11,
						0x22, 0x22, 0x22, 0x22,
						0x33, 0x33, 0x33, 0x33,
					},
				},
			},
		},
		{
			name: "max type space, length 0",
			b: []byte{
				0x04, 0x00,
				0xff, 0xff,
			},
			attrs: []Attribute{
				{
					Length: 4,
					Type:   0xffff,
					Data:   make([]byte, 0),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := UnmarshalAttributes(tt.b)

			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
					want, got)
			}
			if err != nil {
				return
			}

			if want, got := tt.attrs, attrs; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected attributes:\n- want: %v\n-  got: %v",
					want, got)
			}
		})
	}
}

func TestAttributeDecoderError(t *testing.T) {
	bad := []Attribute{{
		Type: 1,
		// Doesn't fit any integer types.
		Data: []byte{0xe, 0xad, 0xbe},
	}}

	skipBigEndian(t)

	tests := []struct {
		name  string
		attrs []Attribute
		fn    func(ad *AttributeDecoder)
	}{
		{
			name:  "uint8",
			attrs: bad,
			fn: func(ad *AttributeDecoder) {
				ad.Uint8()
				ad.Next()
				ad.Uint8()
			},
		},
		{
			name:  "uint16",
			attrs: bad,
			fn: func(ad *AttributeDecoder) {
				ad.Uint16()
				ad.Next()
				ad.Uint16()
			},
		},
		{
			name:  "uint32",
			attrs: bad,
			fn: func(ad *AttributeDecoder) {
				ad.Uint32()
				ad.Next()
				ad.Uint32()
			},
		},
		{
			name:  "uint64",
			attrs: bad,
			fn: func(ad *AttributeDecoder) {
				ad.Uint64()
				ad.Next()
				ad.Uint64()
			},
		},
		{
			name:  "int8",
			attrs: bad,
			fn: func(ad *AttributeDecoder) {
				ad.Int8()
				ad.Next()
				ad.Int8()
			},
		},
		{
			name:  "int16",
			attrs: bad,
			fn: func(ad *AttributeDecoder) {
				ad.Int16()
				ad.Next()
				ad.Int16()
			},
		},
		{
			name:  "int32",
			attrs: bad,
			fn: func(ad *AttributeDecoder) {
				ad.Int32()
				ad.Next()
				ad.Int32()
			},
		},
		{
			name:  "int64",
			attrs: bad,
			fn: func(ad *AttributeDecoder) {
				ad.Int64()
				ad.Next()
				ad.Int64()
			},
		},
		{
			name:  "do",
			attrs: bad,
			fn: func(ad *AttributeDecoder) {
				ad.Do(func(_ []byte) error {
					return errors.New("some error")
				})
				ad.Do(func(_ []byte) error {
					panic("shouldn't be called")
				})
			},
		},
		{
			name: "flag",
			attrs: []Attribute{{
				Type: 1,
				// Flag data is not empty.
				Data: []byte{0xff},
			}},
			fn: func(ad *AttributeDecoder) {
				ad.Flag()
				ad.Next()
				ad.Flag()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := MarshalAttributes(tt.attrs)
			if err != nil {
				t.Fatalf("failed to marshal attributes: %v", err)
			}

			ad, err := NewAttributeDecoder(b)
			if err != nil {
				t.Fatalf("failed to create attribute decoder: %v", err)
			}

			for ad.Next() {
				tt.fn(ad)
			}

			if err := ad.Err(); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestAttributeDecoderOK(t *testing.T) {
	skipBigEndian(t)

	tests := []struct {
		name  string
		attrs []Attribute
		fn    func(ad *AttributeDecoder)
	}{
		{
			name:  "empty",
			attrs: nil,
			fn: func(_ *AttributeDecoder) {
				panic("should not be called")
			},
		},
		{
			name:  "uint-int native endian",
			attrs: adEndianAttrs(native.Endian),
			fn:    adEndianTest(native.Endian),
		},
		{
			name:  "uint-int little endian",
			attrs: adEndianAttrs(binary.LittleEndian),
			fn:    adEndianTest(binary.LittleEndian),
		},
		{
			name:  "uint-int big endian",
			attrs: adEndianAttrs(binary.BigEndian),
			fn:    adEndianTest(binary.BigEndian),
		},
		{
			name: "bytes",
			attrs: []Attribute{{
				Type: 1,
				Data: []byte{0xde, 0xad},
			}},
			fn: func(ad *AttributeDecoder) {
				var b []byte
				switch t := ad.Type(); t {
				case 1:
					b = ad.Bytes()
				default:
					panicf("unhandled attribute type: %d", t)
				}

				if diff := cmp.Diff([]byte{0xde, 0xad}, b); diff != "" {
					panicf("unexpected attribute value (-want +got):\n%s", diff)
				}

				b[0] = 0xff

				if diff := cmp.Diff(b, ad.Bytes()); diff == "" {
					panic("expected attribute value to be copied and different")
				}
			},
		},
		{
			name: "string",
			attrs: []Attribute{{
				Type: 1,
				// The string should be able to contain extra trailing NULL
				// bytes which will all be removed automatically.
				Data: nlenc.Bytes("hello world\x00\x00\x00"),
			}},
			fn: func(ad *AttributeDecoder) {
				var s string
				switch t := ad.Type(); t {
				case 1:
					s = ad.String()
				default:
					panicf("unhandled attribute type: %d", t)
				}

				if diff := cmp.Diff("hello world", s); diff != "" {
					panicf("unexpected attribute value (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "flag",
			attrs: []Attribute{{
				Type: 1,
			}},
			fn: func(ad *AttributeDecoder) {
				var flag bool
				switch t := ad.Type(); t {
				case 1:
					flag = ad.Flag()
				default:
					panicf("unhandled attribute type: %d", t)
				}
				if !flag {
					panic("flag was not set")
				}
			},
		},
		{
			name: "do",
			attrs: []Attribute{
				// Arbitrary C-like structure.
				{
					Type: 1,
					Data: []byte{
						// uint16
						0xde, 0xad,
						// uint8
						0xbe,
						// padding
						0x00,
					},
				},
				// Nested attributes.
				{
					Type: 2,
					Data: func() []byte {
						b, err := MarshalAttributes([]Attribute{{
							Type: 2,
							Data: nlenc.Uint16Bytes(2),
						}})
						if err != nil {
							panicf("failed to marshal test attributes: %v", err)
						}

						return b
					}(),
				},
			},
			fn: func(ad *AttributeDecoder) {
				switch t := ad.Type(); t {
				case 1:
					type cstruct struct {
						A uint16
						B uint8
					}

					want := cstruct{
						// Little-endian is the worst.
						A: 0xadde,
						B: 0xbe,
					}

					ad.Do(func(b []byte) error {
						// unsafe invariant check.
						if want, got := int(unsafe.Sizeof(cstruct{})), len(b); want != got {
							panicf("unexpected struct size: want: %d, got: %d", want, got)
						}

						got := *(*cstruct)(unsafe.Pointer(&b[0]))

						if diff := cmp.Diff(want, got); diff != "" {
							panicf("unexpected struct (-want +got):\n%s", diff)
						}

						return nil
					})
				case 2:
					ad.Do(func(b []byte) error {
						adi, err := NewAttributeDecoder(b)
						if err != nil {
							return err
						}

						var got int
						first := true
						for adi.Next() {
							if !first {
								panic("loop iterated too many times")
							}
							first = false

							if adi.Type() != 2 {
								panicf("unhandled attribute type: %d", t)
							}

							got = int(adi.Uint16())
						}

						if diff := cmp.Diff(2, got); diff != "" {
							panicf("unexpected nested attribute value (-want +got):\n%s", diff)
						}

						return adi.Err()
					})
				default:
					panicf("unhandled attribute type: %d", t)
				}
			},
		},
		{
			name: "nested",
			attrs: []Attribute{
				// Nested attributes.
				{
					Type: Nested | 1,
					Data: func() []byte {
						nb, err := MarshalAttributes([]Attribute{{
							Type: 1,
							Data: nlenc.Uint32Bytes(2),
						}})
						if err != nil {
							panicf("failed to marshal nested test attributes: %v", err)
						}

						b, err := MarshalAttributes([]Attribute{
							{
								Type: 1,
								Data: nlenc.Uint16Bytes(1),
							},
							{
								Type: Nested | 2,
								Data: nb,
							},
						})
						if err != nil {
							panicf("failed to marshal test attributes: %v", err)
						}

						return b
					}(),
				},
			},
			fn: func(ad *AttributeDecoder) {
				if diff := cmp.Diff(uint16(1), ad.Type()); diff != "" {
					panicf("unexpected attribute type (-want +got):\n%s", diff)
				}

				ad.Nested(func(nad *AttributeDecoder) error {
					for nad.Next() {
						switch t := nad.Type(); t {
						case 1:
							if diff := cmp.Diff(uint16(1), nad.Uint16()); diff != "" {
								panicf("unexpected nested uint16 (-want +got):\n%s", diff)
							}
						case 2:
							nad.Nested(func(nnad *AttributeDecoder) error {
								for nad.Next() {
									if diff := cmp.Diff(uint16(1), nnad.Type()); diff != "" {
										panicf("unexpected nested attribute type (-want +got):\n%s", diff)
									}

									if diff := cmp.Diff(uint32(2), nnad.Uint32()); diff != "" {
										panicf("unexpected nested uint32 (-want +got):\n%s", diff)
									}
								}

								return nil
							})
						default:
							panicf("unhandled nested attribute type: %d", t)
						}
					}

					return nil
				})
			},
		},
		{
			name: "typeflags",
			attrs: []Attribute{{
				Type: 0xffff,
			}},
			fn: func(ad *AttributeDecoder) {
				if diff := cmp.Diff(ad.Type(), uint16(0x3fff)); diff != "" {
					panicf("unexpected Type (-want +got):\n%s", diff)
				}

				if diff := cmp.Diff(ad.TypeFlags(), uint16(0xc000)); diff != "" {
					panicf("unexpected TypeFlags (-want +got):\n%s", diff)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := MarshalAttributes(tt.attrs)
			if err != nil {
				t.Fatalf("failed to marshal attributes: %v", err)
			}

			ad, err := NewAttributeDecoder(b)
			if err != nil {
				t.Fatalf("failed to create attribute decoder: %v", err)
			}

			// Len should always report the same number of input attributes.
			if diff := cmp.Diff(len(tt.attrs), ad.Len()); diff != "" {
				t.Fatalf("unexpected  (-want +got):\n%s", diff)
			}

			for ad.Next() {
				tt.fn(ad)
			}

			if err := ad.Err(); err != nil {
				t.Fatalf("failed to decode attributes: %v", err)
			}
		})
	}
}

func adEndianAttrs(order binary.ByteOrder) []Attribute {
	return []Attribute{
		{
			Type: 1,
			Data: func() []byte {
				return []byte{1}
			}(),
		},
		{
			Type: 2,
			Data: func() []byte {
				b := make([]byte, 2)
				order.PutUint16(b, 2)
				return b
			}(),
		},
		{
			Type: 3,
			Data: func() []byte {
				b := make([]byte, 4)
				order.PutUint32(b, 3)
				return b
			}(),
		},
		{
			Type: 4,
			Data: func() []byte {
				b := make([]byte, 8)
				order.PutUint64(b, 4)
				return b
			}(),
		},
		{
			Type: 5,
			Data: func() []byte {
				return []byte{uint8(int8(5))}
			}(),
		},
		{
			Type: 6,
			Data: func() []byte {
				b := make([]byte, 2)
				order.PutUint16(b, uint16(int16(6)))
				return b
			}(),
		},
		{
			Type: 7,
			Data: func() []byte {
				b := make([]byte, 4)
				order.PutUint32(b, uint32(int32(7)))
				return b
			}(),
		},
		{
			Type: 8,
			Data: func() []byte {
				b := make([]byte, 8)
				order.PutUint64(b, uint64(int64(8)))
				return b
			}(),
		},
	}
}

func adEndianTest(order binary.ByteOrder) func(ad *AttributeDecoder) {
	return func(ad *AttributeDecoder) {
		ad.ByteOrder = order

		var (
			t uint16
			v int
		)

		switch t = ad.Type(); t {
		case 1:
			v = int(ad.Uint8())
		case 2:
			v = int(ad.Uint16())
		case 3:
			v = int(ad.Uint32())
		case 4:
			v = int(ad.Uint64())
		case 5:
			v = int(ad.Int8())
		case 6:
			v = int(ad.Int16())
		case 7:
			v = int(ad.Int32())
		case 8:
			v = int(ad.Int64())
		default:
			panicf("unhandled attribute type: %d", t)
		}

		if diff := cmp.Diff(int(t), v); diff != "" {
			panicf("unexpected attribute value (-want +got):\n%s", diff)
		}
	}
}

func TestAttributeEncoderError(t *testing.T) {
	skipBigEndian(t)

	tests := []struct {
		name string
		fn   func(ae *AttributeEncoder)
	}{
		{
			name: "bytes length",
			fn: func(ae *AttributeEncoder) {
				ae.Bytes(1, make([]byte, math.MaxUint16))
			},
		},
		{
			name: "string length",
			fn: func(ae *AttributeEncoder) {
				ae.String(1, string(make([]byte, math.MaxUint16)))
			},
		},
		{
			name: "do length",
			fn: func(ae *AttributeEncoder) {
				ae.Do(1, func() ([]byte, error) {
					return make([]byte, math.MaxUint16), nil
				})
			},
		},
		{
			name: "do function",
			fn: func(ae *AttributeEncoder) {
				ae.Do(1, func() ([]byte, error) {
					return nil, errors.New("testing error")
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ae := NewAttributeEncoder()
			tt.fn(ae)
			_, err := ae.Encode()

			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestAttributeEncoderOK(t *testing.T) {
	skipBigEndian(t)

	tests := []struct {
		name   string
		attrs  []Attribute
		endian binary.ByteOrder
		fn     func(ae *AttributeEncoder)
	}{
		{
			name:  "empty",
			attrs: nil,
			fn: func(_ *AttributeEncoder) {
			},
		},
		{
			name:  "uint-int native endian",
			attrs: adEndianAttrs(native.Endian),
			fn:    aeEndianTest(native.Endian),
		},
		{
			name:   "uint-int little endian",
			attrs:  adEndianAttrs(binary.LittleEndian),
			endian: binary.LittleEndian,
			fn:     aeEndianTest(binary.LittleEndian),
		},
		{
			name:   "uint-int big endian",
			attrs:  adEndianAttrs(binary.BigEndian),
			endian: binary.BigEndian,
			fn:     aeEndianTest(binary.BigEndian),
		},
		{
			name:  "flag true",
			attrs: []Attribute{{Type: 1}},
			fn: func(ae *AttributeEncoder) {
				ae.Flag(1, true)
			},
		},
		{
			name:  "flag false",
			attrs: []Attribute{},
			fn: func(ae *AttributeEncoder) {
				ae.Flag(1, false)
			},
		},
		{
			name: "string",
			attrs: []Attribute{{
				Type: 1,
				Data: nlenc.Bytes("hello netlink"),
			}},
			fn: func(ae *AttributeEncoder) {
				ae.String(1, "hello netlink")
			},
		},
		{
			name: "byte",
			attrs: []Attribute{
				{
					Type: 1,
					Data: []byte{0xde, 0xad},
				},
			},
			fn: func(ae *AttributeEncoder) {
				ae.Bytes(1, []byte{0xde, 0xad})
			},
		},
		{
			name: "do",
			attrs: []Attribute{
				// Arbitrary C-like structure.
				{
					Type: 1,
					Data: []byte{0xde, 0xad, 0xbe},
				},
				// Nested attributes.
				{
					Type: 2,
					Data: func() []byte {
						b, err := MarshalAttributes([]Attribute{{
							Type: 2,
							Data: nlenc.Uint16Bytes(2),
						}})
						if err != nil {
							panicf("failed to marshal test attributes: %v", err)
						}

						return b
					}(),
				},
			},
			fn: func(ae *AttributeEncoder) {
				ae.Do(1, func() ([]byte, error) {
					return []byte{0xde, 0xad, 0xbe}, nil
				})
				ae.Do(2, func() ([]byte, error) {
					ae1 := NewAttributeEncoder()
					ae1.Uint16(2, 2)
					return ae1.Encode()
				})
			},
		},
		{
			name: "nested",
			attrs: []Attribute{
				// Nested attributes.
				{
					Type: Nested | 1,
					Data: func() []byte {
						nb, err := MarshalAttributes([]Attribute{{
							Type: 1,
							Data: nlenc.Uint32Bytes(2),
						}})
						if err != nil {
							panicf("failed to marshal nested test attributes: %v", err)
						}

						b, err := MarshalAttributes([]Attribute{
							{
								Type: 1,
								Data: nlenc.Uint16Bytes(1),
							},
							{
								Type: Nested | 2,
								Data: nb,
							},
						})
						if err != nil {
							panicf("failed to marshal test attributes: %v", err)
						}

						return b
					}(),
				},
			},
			fn: func(ae *AttributeEncoder) {
				ae.Nested(1, func(nae *AttributeEncoder) error {
					nae.Uint16(1, 1)
					nae.Nested(2, func(nnae *AttributeEncoder) error {
						nnae.Uint32(1, 2)
						return nil
					})
					return nil
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := MarshalAttributes(tt.attrs)
			if err != nil {
				t.Fatalf("failed to marshal attributes: %v", err)
			}

			ae := NewAttributeEncoder()
			tt.fn(ae)
			got, err := ae.Encode()
			if err != nil {
				t.Fatalf("failed to encode attributes: %v", err)
			}

			if diff := cmp.Diff(got, b); diff != "" {
				t.Fatalf("unexpected attribute encoding (-want +got):\n%s", diff)
			}
		})
	}
}

func aeEndianTest(order binary.ByteOrder) func(ae *AttributeEncoder) {
	return func(ae *AttributeEncoder) {
		ae.ByteOrder = order

		ae.Uint8(1, uint8(1))
		ae.Uint16(2, uint16(2))
		ae.Uint32(3, uint32(3))
		ae.Uint64(4, uint64(4))
		ae.Int8(5, int8(5))
		ae.Int16(6, int16(6))
		ae.Int32(7, int32(7))
		ae.Int64(8, int64(8))
	}
}
