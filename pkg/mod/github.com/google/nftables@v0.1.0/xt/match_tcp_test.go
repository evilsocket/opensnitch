package xt

import (
	"reflect"
	"testing"
)

func TestMatchTcp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		info InfoAny
	}{
		{
			name: "un/marshal Tcp round-trip",
			info: &Tcp{
				SrcPorts:  [2]uint16{0x1234, 0x5678},
				DstPorts:  [2]uint16{0x2345, 0x6789},
				Option:    0x12,
				FlagsMask: 0x34,
				FlagsCmp:  0x56,
				InvFlags:  0x78,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.info.marshal(0, 0)
			if err != nil {
				t.Fatalf("marshal error: %+v", err)

			}
			var recoveredInfo InfoAny = &Tcp{}
			err = recoveredInfo.unmarshal(0, 0, data)
			if err != nil {
				t.Fatalf("unmarshal error: %+v", err)
			}
			if !reflect.DeepEqual(tt.info, recoveredInfo) {
				t.Fatalf("original %+v and recovered %+v are different", tt.info, recoveredInfo)
			}
		})
	}
}
