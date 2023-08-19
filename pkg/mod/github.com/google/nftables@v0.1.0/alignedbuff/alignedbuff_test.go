package alignedbuff

import (
	"testing"
)

func TestAlignmentData(t *testing.T) {
	if uint16AlignMask == 0 {
		t.Fatal("zero uint16 alignment mask")
	}
	if uint32AlignMask == 0 {
		t.Fatal("zero uint32 alignment mask")
	}
	if uint64AlignMask == 0 {
		t.Fatal("zero uint64 alignment mask")
	}
	if len(padding) == 0 {
		t.Fatal("zero alignment padding sequence")
	}
	if uintSize == 0 {
		t.Fatal("zero uint size")
	}
	if int32AlignMask == 0 {
		t.Fatal("zero uint32 alignment mask")
	}
}

func TestAlignedBuff8(t *testing.T) {
	b := NewWithData([]byte{0x42})
	tests := []struct {
		name string
		v    uint8
		err  error
	}{
		{
			name: "first read",
			v:    0x42,
			err:  nil,
		},
		{
			name: "end of buffer",
			v:    0,
			err:  ErrEOF,
		},
	}

	for _, tt := range tests {
		v, err := b.Uint8()
		if v != tt.v || err != tt.err {
			t.Errorf("expected: %#v %#v, got: %#v, %#v",
				tt.v, tt.err, v, err)
		}
	}
}

func TestAlignedBuff16(t *testing.T) {
	b0 := New()
	b0.PutUint8(0x42)
	b0.PutUint16(0x1234)
	b0.PutUint16(0x5678)

	b := NewWithData(b0.data)
	v, err := b.Uint8()
	if v != 0x42 || err != nil {
		t.Fatalf("unaligment read failed")
	}
	tests := []struct {
		name string
		v    uint16
		err  error
	}{
		{
			name: "first read",
			v:    0x1234,
			err:  nil,
		},
		{
			name: "second read",
			v:    0x5678,
			err:  nil,
		},
		{
			name: "end of buffer",
			v:    0,
			err:  ErrEOF,
		},
	}

	for _, tt := range tests {
		v, err := b.Uint16()
		if v != tt.v || err != tt.err {
			t.Errorf("%s failed, expected: %#v %#v, got: %#v, %#v",
				tt.name, tt.v, tt.err, v, err)
		}
	}
}

func TestAlignedBuff32(t *testing.T) {
	b0 := New()
	b0.PutUint8(0x42)
	b0.PutUint32(0x12345678)
	b0.PutUint32(0x01cecafe)

	b := NewWithData(b0.data)

	if len(b0.Data()) != 4*4 {
		t.Fatalf("alignment padding failed")
	}

	v, err := b.Uint8()
	if v != 0x42 || err != nil {
		t.Fatalf("unaligment read failed")
	}
	tests := []struct {
		name string
		v    uint32
		err  error
	}{
		{
			name: "first read",
			v:    0x12345678,
			err:  nil,
		},
		{
			name: "second read",
			v:    0x01cecafe,
			err:  nil,
		},
		{
			name: "end of buffer",
			v:    0,
			err:  ErrEOF,
		},
	}

	for _, tt := range tests {
		v, err := b.Uint32()
		if v != tt.v || err != tt.err {
			t.Errorf("expected: %#v %#v, got: %#v, %#v",
				tt.v, tt.err, v, err)
		}
	}
}

func TestAlignedBuff64(t *testing.T) {
	b0 := New()
	b0.PutUint8(0x42)
	b0.PutUint64(0x1234567823456789)
	b0.PutUint64(0x01cecafec001beef)

	b := NewWithData(b0.data)
	v, err := b.Uint8()
	if v != 0x42 || err != nil {
		t.Fatalf("unaligment read failed")
	}
	tests := []struct {
		name string
		v    uint64
		err  error
	}{
		{
			name: "first read",
			v:    0x1234567823456789,
			err:  nil,
		},
		{
			name: "second read",
			v:    0x01cecafec001beef,
			err:  nil,
		},
		{
			name: "end of buffer",
			v:    0,
			err:  ErrEOF,
		},
	}

	for _, tt := range tests {
		v, err := b.Uint64()
		if v != tt.v || err != tt.err {
			t.Errorf("expected: %#v %#v, got: %#v, %#v",
				tt.v, tt.err, v, err)
		}
	}
}

func TestAlignedUint(t *testing.T) {
	expectedv := uint(^uint32(0) - 1)
	b0 := New()
	b0.PutUint8(0x55)
	b0.PutUint(expectedv)
	b0.PutUint8(0xAA)

	b := NewWithData(b0.data)
	v, err := b.Uint8()
	if v != 0x55 || err != nil {
		t.Fatalf("sentinel read failed")
	}
	uiv, err := b.Uint()
	if uiv != expectedv || err != nil {
		t.Fatalf("uint read failed, expected: %d, got: %d", expectedv, uiv)
	}
	v, err = b.Uint8()
	if v != 0xAA || err != nil {
		t.Fatalf("sentinel read failed")
	}
}

func TestAlignedBuffInt32(t *testing.T) {
	b0 := New()
	b0.PutUint8(0x42)
	b0.PutInt32(0x12345678)
	b0.PutInt32(0x01cecafe)

	b := NewWithData(b0.data)

	if len(b0.Data()) != 4*4 {
		t.Fatalf("alignment padding failed")
	}

	v, err := b.Uint8()
	if v != 0x42 || err != nil {
		t.Fatalf("unaligment read failed")
	}
	tests := []struct {
		name string
		v    int32
		err  error
	}{
		{
			name: "first read",
			v:    0x12345678,
			err:  nil,
		},
		{
			name: "second read",
			v:    0x01cecafe,
			err:  nil,
		},
		{
			name: "end of buffer",
			v:    0,
			err:  ErrEOF,
		},
	}

	for _, tt := range tests {
		v, err := b.Int32()
		if v != tt.v || err != tt.err {
			t.Errorf("expected: %#v %#v, got: %#v, %#v",
				tt.v, tt.err, v, err)
		}
	}
}

func TestAlignedBuffPutNullTerminatedString(t *testing.T) {
	b0 := New()
	b0.PutUint8(0x42)
	b0.PutString("test" + "\x00")

	b := NewWithData(b0.data)

	v, err := b.Uint8()
	if v != 0x42 || err != nil {
		t.Fatalf("unaligment read failed")
	}
	tests := []struct {
		name string
		v    string
		err  error
	}{
		{
			name: "first read",
			v:    "test",
			err:  nil,
		},
	}

	for _, tt := range tests {
		v, err := b.String()
		if v != tt.v || err != tt.err {
			t.Errorf("expected: %#v %#v, got: %#v, %#v",
				tt.v, tt.err, v, err)
		}
	}
}

func TestAlignedBuffPutString(t *testing.T) {
	b0 := New()
	b0.PutUint8(0x42)
	b0.PutString("test")

	b := NewWithData(b0.data)

	v, err := b.Uint8()
	if v != 0x42 || err != nil {
		t.Fatalf("unaligment read failed")
	}
	tests := []struct {
		name string
		v    string
		err  error
	}{
		{
			name: "first read",
			v:    "test",
			err:  nil,
		},
	}

	for _, tt := range tests {
		v, err := b.StringWithLength(len("test"))
		if v != tt.v || err != tt.err {
			t.Errorf("expected: %#v %#v, got: %#v, %#v",
				tt.v, tt.err, v, err)
		}
	}
}
