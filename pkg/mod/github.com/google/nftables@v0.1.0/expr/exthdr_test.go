package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestExthdr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		eh   Exthdr
	}{
		{
			name: "Unmarshal Exthdr DestRegister case",
			eh: Exthdr{
				DestRegister:   1,
				Type:           2,
				Offset:         3,
				Len:            4,
				Flags:          5,
				Op:             ExthdrOpTcpopt,
				SourceRegister: 0,
			},
		},
		{
			name: "Unmarshal Exthdr SourceRegister case",
			eh: Exthdr{
				SourceRegister: 1,
				Type:           2,
				Offset:         3,
				Len:            4,
				Op:             ExthdrOpTcpopt,
				DestRegister:   0,
				Flags:          0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			neh := Exthdr{}
			data, err := tt.eh.marshal(0 /* don't care in this test */)
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
					if err := neh.unmarshal(0, ad.Bytes()); err != nil {
						t.Errorf("unmarshal error: %+v", err)
						break
					}
				}
			}
			if !reflect.DeepEqual(tt.eh, neh) {
				t.Fatalf("original %+v and recovered %+v Exthdr structs are different", tt.eh, neh)
			}
		})
	}
}
