package xt

import (
	"reflect"
	"testing"
)

func TestTargetAddrType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		fam   byte
		rev   uint32
		info  InfoAny
		empty InfoAny
	}{
		{
			name: "un/marshal AddrType Rev 0 round-trip",
			fam:  0,
			rev:  0,
			info: &AddrType{
				Source:       0x1234,
				Dest:         0x5678,
				InvertSource: true,
				InvertDest:   false,
			},
			empty: &AddrType{},
		},
		{
			name: "un/marshal AddrType Rev 0 round-trip",
			fam:  0,
			rev:  0,
			info: &AddrType{
				Source:       0x1234,
				Dest:         0x5678,
				InvertSource: false,
				InvertDest:   true,
			},
			empty: &AddrType{},
		},
		{
			name: "un/marshal AddrType Rev 1 round-trip",
			fam:  0,
			rev:  0,
			info: &AddrTypeV1{
				Source: 0x1234,
				Dest:   0x5678,
				Flags:  0xb00f,
			},
			empty: &AddrTypeV1{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.info.marshal(TableFamily(tt.fam), tt.rev)
			if err != nil {
				t.Fatalf("marshal error: %+v", err)

			}
			var recoveredInfo InfoAny = tt.empty
			err = recoveredInfo.unmarshal(TableFamily(tt.fam), tt.rev, data)
			if err != nil {
				t.Fatalf("unmarshal error: %+v", err)
			}
			if !reflect.DeepEqual(tt.info, recoveredInfo) {
				t.Fatalf("original %+v and recovered %+v are different", tt.info, recoveredInfo)
			}
		})
	}
}
