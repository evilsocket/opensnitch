package netlink_test

import (
	"testing"

	"github.com/mdlayher/netlink"
)

var attrBench = []struct {
	name  string
	attrs []netlink.Attribute
}{
	{
		name: "0",
	},
	{
		name:  "1",
		attrs: makeAttributes(1),
	},
	{
		name:  "8",
		attrs: makeAttributes(8),
	},
	{
		name:  "64",
		attrs: makeAttributes(64),
	},
	{
		name:  "512",
		attrs: makeAttributes(512),
	},
}

func BenchmarkMarshalAttributes(b *testing.B) {
	for _, tt := range attrBench {
		b.Run(tt.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				if _, err := netlink.MarshalAttributes(tt.attrs); err != nil {
					b.Fatalf("failed to marshal: %v", err)
				}
			}
		})
	}
}

func BenchmarkUnmarshalAttributes(b *testing.B) {
	for _, tt := range attrBench {
		b.Run(tt.name, func(b *testing.B) {
			buf, err := netlink.MarshalAttributes(tt.attrs)
			if err != nil {
				b.Fatalf("failed to marshal: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				if _, err := netlink.UnmarshalAttributes(buf); err != nil {
					b.Fatalf("failed to unmarshal: %v", err)
				}
			}
		})
	}
}

func makeAttributes(n int) []netlink.Attribute {
	attrs := make([]netlink.Attribute, 0, n)
	for i := 0; i < n; i++ {
		attrs = append(attrs, netlink.Attribute{
			Type: uint16(i),
			Data: make([]byte, n),
		})
	}

	return attrs
}
