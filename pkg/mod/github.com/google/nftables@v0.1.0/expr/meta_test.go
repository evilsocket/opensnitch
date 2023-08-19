package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestMeta(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		meta Meta
	}{
		{
			name: "Unmarshal Meta DestRegister case",
			meta: Meta{
				Key:            1,
				SourceRegister: false,
				Register:       1,
			},
		},
		{
			name: "Unmarshal Meta SourceRegister case",
			meta: Meta{
				Key:            1,
				SourceRegister: true,
				Register:       1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nMeta := Meta{}
			data, err := tt.meta.marshal(0 /* don't care in this test */)
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
					if err := nMeta.unmarshal(0, ad.Bytes()); err != nil {
						t.Errorf("unmarshal error: %+v", err)
						break
					}
				}
			}
			if !reflect.DeepEqual(tt.meta, nMeta) {
				t.Fatalf("original %+v and recovered %+v Exthdr structs are different", tt.meta, nMeta)
			}
		})
	}
}
