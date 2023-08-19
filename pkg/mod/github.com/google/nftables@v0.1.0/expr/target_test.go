package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/google/nftables/xt"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestTarget(t *testing.T) {
	t.Parallel()
	payload := xt.Unknown([]byte{0xb0, 0x1d, 0xca, 0xfe, 0x00})
	tests := []struct {
		name string
		tgt  Target
	}{
		{
			name: "Unmarshal Target case",
			tgt: Target{
				Name: "foobar",
				Rev:  1234567890,
				Info: &payload,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ntgt := Target{}
			data, err := tt.tgt.marshal(0 /* don't care in this test */)
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
					if err := ntgt.unmarshal(0 /* don't care in this test */, ad.Bytes()); err != nil {
						t.Errorf("unmarshal error: %+v", err)
						break
					}
				}
			}
			if !reflect.DeepEqual(tt.tgt, ntgt) {
				t.Fatalf("original %+v and recovered %+v Target structs are different", tt.tgt, ntgt)
			}
		})
	}
}
