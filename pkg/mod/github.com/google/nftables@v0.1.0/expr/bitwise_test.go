package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestBitwise(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		bw   Bitwise
	}{
		{
			name: "Unmarshal Bitwise IPv4 case",
			bw: Bitwise{
				SourceRegister: 1,
				DestRegister:   2,
				Len:            4,
				// By specifying Xor to 0x0,0x0,0x0,0x0 and Mask to 0xff,0xff,0x0,0x0
				// an expression will match /16 IPv4 address.
				Xor:  []byte{0x0, 0x0, 0x0, 0x0},
				Mask: []byte{0xff, 0xff, 0x0, 0x0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nbw := Bitwise{}
			data, err := tt.bw.marshal(0 /* don't care in this test */)
			if err != nil {
				t.Fatalf("marshal error: %+v", err)

			}
			ad, err := netlink.NewAttributeDecoder(data)
			if err != nil {
				t.Fatalf("NewAttributeDecoder() error: %+v", err)
			}
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				if ad.Type() == unix.NFTA_EXPR_DATA {
					if err := nbw.unmarshal(0, ad.Bytes()); err != nil {
						t.Errorf("unmarshal error: %+v", err)
						break
					}
				}
			}
			if !reflect.DeepEqual(tt.bw, nbw) {
				t.Fatalf("original %+v and recovered %+v Bitwise structs are different", tt.bw, nbw)
			}
		})
	}
}
