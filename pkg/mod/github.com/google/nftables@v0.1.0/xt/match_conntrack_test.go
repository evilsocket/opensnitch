package xt

import (
	"net"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMatchConntrack(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		fam   byte
		rev   uint32
		info  InfoAny
		empty InfoAny
	}{
		{
			name: "un/marshal ConntrackMtinfo1 IPv4 round-trip",
			fam:  unix.NFPROTO_IPV4,
			rev:  0,
			info: &ConntrackMtinfo1{
				ConntrackMtinfoBase: ConntrackMtinfoBase{
					OrigSrcAddr: net.ParseIP("1.2.3.4").To4(),
					OrigSrcMask: net.IPv4Mask(0x12, 0x23, 0x34, 0x45), // only for test ;)
					OrigDstAddr: net.ParseIP("2.3.4.5").To4(),
					OrigDstMask: net.IPv4Mask(0x23, 0x34, 0x45, 0x56), // only for test ;)
					ReplSrcAddr: net.ParseIP("10.20.30.40").To4(),
					ReplSrcMask: net.IPv4Mask(0xf2, 0xe3, 0xd4, 0xc5), // only for test ;)
					ReplDstAddr: net.ParseIP("2.3.4.5").To4(),
					ReplDstMask: net.IPv4Mask(0xe3, 0xd4, 0xc5, 0xb6), // only for test ;)
					ExpiresMin:  0x1234,
					ExpiresMax:  0x2345,
					L4Proto:     0xaa55,
					OrigSrcPort: 123,
					OrigDstPort: 321,
					ReplSrcPort: 789,
					ReplDstPort: 987,
					MatchFlags:  0x01,
					InvertFlags: 0x01,
				},
				StateMask:  0x55,
				StatusMask: 0xaa,
			},
			empty: &ConntrackMtinfo1{},
		},
		{
			name: "un/marshal ConntrackMtinfo1 IPv6 round-trip",
			fam:  unix.NFPROTO_IPV6,
			rev:  0,
			info: &ConntrackMtinfo1{
				ConntrackMtinfoBase: ConntrackMtinfoBase{
					OrigSrcAddr: net.ParseIP("fe80::dead:f001"),
					OrigSrcMask: net.IPMask{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
					OrigDstAddr: net.ParseIP("fd00::dead:f001"),
					OrigDstMask: net.IPMask{0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
					ReplSrcAddr: net.ParseIP("fe80::c01d:cafe"),
					ReplSrcMask: net.IPMask{0x21, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
					ReplDstAddr: net.ParseIP("fd00::c01d:cafe"),
					ReplDstMask: net.IPMask{0x31, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
					ExpiresMin:  0x1234,
					ExpiresMax:  0x2345,
					L4Proto:     0xaa55,
					OrigSrcPort: 123,
					OrigDstPort: 321,
					ReplSrcPort: 789,
					ReplDstPort: 987,
					MatchFlags:  0x01,
					InvertFlags: 0x01,
				},
				StateMask:  0x55,
				StatusMask: 0xaa,
			},
			empty: &ConntrackMtinfo1{},
		},
		{
			name: "un/marshal ConntrackMtinfo2 IPv4 round-trip",
			fam:  unix.NFPROTO_IPV4,
			rev:  0,
			info: &ConntrackMtinfo2{
				ConntrackMtinfoBase: ConntrackMtinfoBase{
					OrigSrcAddr: net.ParseIP("1.2.3.4").To4(),
					OrigSrcMask: net.IPv4Mask(0x12, 0x23, 0x34, 0x45), // only for test ;)
					OrigDstAddr: net.ParseIP("2.3.4.5").To4(),
					OrigDstMask: net.IPv4Mask(0x23, 0x34, 0x45, 0x56), // only for test ;)
					ReplSrcAddr: net.ParseIP("10.20.30.40").To4(),
					ReplSrcMask: net.IPv4Mask(0xf2, 0xe3, 0xd4, 0xc5), // only for test ;)
					ReplDstAddr: net.ParseIP("2.3.4.5").To4(),
					ReplDstMask: net.IPv4Mask(0xe3, 0xd4, 0xc5, 0xb6), // only for test ;)
					ExpiresMin:  0x1234,
					ExpiresMax:  0x2345,
					L4Proto:     0xaa55,
					OrigSrcPort: 123,
					OrigDstPort: 321,
					ReplSrcPort: 789,
					ReplDstPort: 987,
					MatchFlags:  0x01,
					InvertFlags: 0x01,
				},
				StateMask:  0x55aa,
				StatusMask: 0xaa55,
			},
			empty: &ConntrackMtinfo2{},
		},
		{
			name: "un/marshal ConntrackMtinfo1 IPv6 round-trip",
			fam:  unix.NFPROTO_IPV6,
			rev:  0,
			info: &ConntrackMtinfo2{
				ConntrackMtinfoBase: ConntrackMtinfoBase{
					OrigSrcAddr: net.ParseIP("fe80::dead:f001"),
					OrigSrcMask: net.IPMask{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
					OrigDstAddr: net.ParseIP("fd00::dead:f001"),
					OrigDstMask: net.IPMask{0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
					ReplSrcAddr: net.ParseIP("fe80::c01d:cafe"),
					ReplSrcMask: net.IPMask{0x21, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
					ReplDstAddr: net.ParseIP("fd00::c01d:cafe"),
					ReplDstMask: net.IPMask{0x31, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
					ExpiresMin:  0x1234,
					ExpiresMax:  0x2345,
					L4Proto:     0xaa55,
					OrigSrcPort: 123,
					OrigDstPort: 321,
					ReplSrcPort: 789,
					ReplDstPort: 987,
					MatchFlags:  0x01,
					InvertFlags: 0x01,
				},
				StateMask:  0x55aa,
				StatusMask: 0xaa55,
			},
			empty: &ConntrackMtinfo2{},
		},
		{
			name: "un/marshal ConntrackMtinfo3 IPv4 round-trip",
			fam:  unix.NFPROTO_IPV4,
			rev:  0,
			info: &ConntrackMtinfo3{
				ConntrackMtinfo2: ConntrackMtinfo2{
					ConntrackMtinfoBase: ConntrackMtinfoBase{
						OrigSrcAddr: net.ParseIP("1.2.3.4").To4(),
						OrigSrcMask: net.IPv4Mask(0x12, 0x23, 0x34, 0x45), // only for test ;)
						OrigDstAddr: net.ParseIP("2.3.4.5").To4(),
						OrigDstMask: net.IPv4Mask(0x23, 0x34, 0x45, 0x56), // only for test ;)
						ReplSrcAddr: net.ParseIP("10.20.30.40").To4(),
						ReplSrcMask: net.IPv4Mask(0xf2, 0xe3, 0xd4, 0xc5), // only for test ;)
						ReplDstAddr: net.ParseIP("2.3.4.5").To4(),
						ReplDstMask: net.IPv4Mask(0xe3, 0xd4, 0xc5, 0xb6), // only for test ;)
						ExpiresMin:  0x1234,
						ExpiresMax:  0x2345,
						L4Proto:     0xaa55,
						OrigSrcPort: 123,
						OrigDstPort: 321,
						ReplSrcPort: 789,
						ReplDstPort: 987,
						MatchFlags:  0x01,
						InvertFlags: 0x01,
					},
					StateMask:  0x55aa,
					StatusMask: 0xaa55,
				},
				OrigSrcPortHigh: 0xabcd,
				OrigDstPortHigh: 0xcdba,
				ReplSrcPortHigh: 0x1234,
				ReplDstPortHigh: 0x4321,
			},
			empty: &ConntrackMtinfo3{},
		},
		{
			name: "un/marshal ConntrackMtinfo1 IPv6 round-trip",
			fam:  unix.NFPROTO_IPV6,
			rev:  0,
			info: &ConntrackMtinfo3{
				ConntrackMtinfo2: ConntrackMtinfo2{
					ConntrackMtinfoBase: ConntrackMtinfoBase{
						OrigSrcAddr: net.ParseIP("fe80::dead:f001"),
						OrigSrcMask: net.IPMask{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
						OrigDstAddr: net.ParseIP("fd00::dead:f001"),
						OrigDstMask: net.IPMask{0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
						ReplSrcAddr: net.ParseIP("fe80::c01d:cafe"),
						ReplSrcMask: net.IPMask{0x21, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
						ReplDstAddr: net.ParseIP("fd00::c01d:cafe"),
						ReplDstMask: net.IPMask{0x31, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, // only for test ;)
						ExpiresMin:  0x1234,
						ExpiresMax:  0x2345,
						L4Proto:     0xaa55,
						OrigSrcPort: 123,
						OrigDstPort: 321,
						ReplSrcPort: 789,
						ReplDstPort: 987,
						MatchFlags:  0x01,
						InvertFlags: 0x01,
					},
					StateMask:  0x55aa,
					StatusMask: 0xaa55,
				},
				OrigSrcPortHigh: 0xabcd,
				OrigDstPortHigh: 0xcdba,
				ReplSrcPortHigh: 0x1234,
				ReplDstPortHigh: 0x4321,
			},
			empty: &ConntrackMtinfo3{},
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
