package xt

import (
	"reflect"
	"testing"
)

func TestUnknown(t *testing.T) {
	t.Parallel()
	payload := Unknown([]byte{0xb0, 0x1d, 0xca, 0xfe, 0x00})
	tests := []struct {
		name string
		info InfoAny
	}{
		{
			name: "un/marshal Unknown round-trip",
			info: &payload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.info.marshal(0, 0)
			if err != nil {
				t.Fatalf("marshal error: %+v", err)

			}
			var recoveredInfo InfoAny = &Unknown{}
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
