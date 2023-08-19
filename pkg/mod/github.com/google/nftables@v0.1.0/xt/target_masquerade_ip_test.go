package xt

import (
	"net"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTargetMasqueradeIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		fam   byte
		rev   uint32
		info  InfoAny
		empty InfoAny
	}{
		{
			name: "un/marshal NatIPv4Range round-trip",
			fam:  unix.NFPROTO_IPV4,
			rev:  0,
			info: &NatIPv4MultiRangeCompat{
				NatIPv4Range{
					Flags:   0x1234,
					MinIP:   net.ParseIP("12.23.34.45").To4(),
					MaxIP:   net.ParseIP("21.32.43.54").To4(),
					MinPort: 0x5678,
					MaxPort: 0xabcd,
				},
			},
			empty: new(NatIPv4MultiRangeCompat),
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
