package binaryutil

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
	"unsafe"
)

func TestNativeByteOrder(t *testing.T) {
	// See https://stackoverflow.com/a/53286786
	var natEnd binary.ByteOrder

	canary := [2]byte{}
	*(*uint16)(unsafe.Pointer(&canary[0])) = uint16(0xABCD)

	switch canary {
	case [2]byte{0xCD, 0xAB}:
		natEnd = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		natEnd = binary.BigEndian
	default:
		t.Fatalf("unsupported \"mixed\" native endianness")
	}

	tests := []struct {
		name      string
		expectedv interface{}
		marshal   func(v interface{}) []byte
		unmarshal func(b []byte) interface{}
		reference func(v interface{}, b []byte)
	}{
		{
			name:      "Uint16",
			expectedv: uint16(0x1234),
			marshal:   func(v interface{}) []byte { return NativeEndian.PutUint16(v.(uint16)) },
			unmarshal: func(b []byte) interface{} { return NativeEndian.Uint16(b) },
			reference: func(v interface{}, b []byte) { natEnd.PutUint16(b, v.(uint16)) },
		},
		{
			name:      "Uint32",
			expectedv: uint32(0x12345678),
			marshal:   func(v interface{}) []byte { return NativeEndian.PutUint32(v.(uint32)) },
			unmarshal: func(b []byte) interface{} { return NativeEndian.Uint32(b) },
			reference: func(v interface{}, b []byte) { natEnd.PutUint32(b, v.(uint32)) },
		},
		{
			name:      "Uint64",
			expectedv: uint64(0x1234567801020304),
			marshal:   func(v interface{}) []byte { return NativeEndian.PutUint64(v.(uint64)) },
			unmarshal: func(b []byte) interface{} { return NativeEndian.Uint64(b) },
			reference: func(v interface{}, b []byte) { natEnd.PutUint64(b, v.(uint64)) },
		},
	}

	for _, tt := range tests {
		expectedb := make([]byte, reflect.TypeOf(tt.expectedv).Size())
		tt.reference(tt.expectedv, expectedb)
		actualb := tt.marshal(tt.expectedv)
		if !bytes.Equal(actualb, expectedb) {
			t.Errorf("NativeEndian.Put%s failure, expected: %#v, got: %#v", tt.name, expectedb, actualb)
		}
		actualv := tt.unmarshal(actualb)
		if !reflect.DeepEqual(tt.expectedv, actualv) {
			t.Errorf("NativeEndian.%s failure, expected: %#v, got: %#v", tt.name, tt.expectedv, actualv)
		}
	}
}

func TestBigEndian(t *testing.T) {
	tests := []struct {
		name      string
		expected  []byte
		expectedv interface{}
		actual    []byte
		unmarshal func(b []byte) interface{}
	}{
		{
			name:      "Uint16",
			expected:  []byte{0x12, 0x34},
			expectedv: uint16(0x1234),
			actual:    BigEndian.PutUint16(0x1234),
			unmarshal: func(b []byte) interface{} { return BigEndian.Uint16(b) },
		},
		{
			name:      "Uint32",
			expected:  []byte{0x12, 0x34, 0x56, 0x78},
			expectedv: uint32(0x12345678),
			actual:    BigEndian.PutUint32(0x12345678),
			unmarshal: func(b []byte) interface{} { return BigEndian.Uint32(b) },
		},
		{
			name:      "Uint64",
			expected:  []byte{0x12, 0x34, 0x56, 0x78, 0x01, 0x02, 0x03, 0x04},
			expectedv: uint64(0x1234567801020304),
			actual:    BigEndian.PutUint64(0x1234567801020304),
			unmarshal: func(b []byte) interface{} { return BigEndian.Uint64(b) },
		},
	}
	for _, tt := range tests {
		if bytes.Compare(tt.actual, tt.expected) != 0 {
			t.Errorf("BigEndian.Put%s failure, expected: %#v, got: %#v", tt.name, tt.expected, tt.actual)
		}
		if actual := tt.unmarshal(tt.actual); !reflect.DeepEqual(actual, tt.expectedv) {
			t.Errorf("BigEndian.%s failure, expected: %#v, got: %#v", tt.name, tt.expectedv, actual)
		}
	}
}

func TestOtherTypes(t *testing.T) {
	tests := []struct {
		name      string
		expected  []byte
		expectedv interface{}
		actual    []byte
		unmarshal func(b []byte) interface{}
	}{
		{
			name:      "Int32",
			expected:  []byte{0x78, 0x56, 0x34, 0x12},
			expectedv: int32(0x12345678),
			actual:    PutInt32(0x12345678),
			unmarshal: func(b []byte) interface{} { return Int32(b) },
		},
		{
			name:      "String",
			expected:  []byte{0x74, 0x65, 0x73, 0x74},
			expectedv: "test",
			actual:    PutString("test"),
			unmarshal: func(b []byte) interface{} { return String(b) },
		},
	}
	for _, tt := range tests {
		if bytes.Compare(tt.actual, tt.expected) != 0 {
			t.Errorf("Put%s failure, expected: %#v, got: %#v", tt.name, tt.expected, tt.actual)
		}
		if actual := tt.unmarshal(tt.actual); !reflect.DeepEqual(actual, tt.expectedv) {
			t.Errorf("%s failure, expected: %#v, got: %#v", tt.name, tt.expectedv, actual)
		}
	}
}
