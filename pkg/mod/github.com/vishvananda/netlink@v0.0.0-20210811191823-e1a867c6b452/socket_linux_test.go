package netlink

import (
	"reflect"
	"syscall"
	"testing"
)

func TestAttrsToInetDiagTCPInfoResp(t *testing.T) {
	tests := []struct {
		name     string
		attrs    []syscall.NetlinkRouteAttr
		expected *InetDiagTCPInfoResp
		wantFail bool
	}{
		{
			name:     "Empty",
			attrs:    []syscall.NetlinkRouteAttr{},
			expected: &InetDiagTCPInfoResp{},
		},
		{
			name: "BBRInfo Only",
			attrs: []syscall.NetlinkRouteAttr{
				{
					Attr: syscall.RtAttr{
						Len:  20,
						Type: INET_DIAG_BBRINFO,
					},
					Value: []byte{
						100, 0, 0, 0, 0, 0, 0, 0,
						111, 0, 0, 0,
						222, 0, 0, 0,
						123, 0, 0, 0,
					},
				},
			},
			expected: &InetDiagTCPInfoResp{
				TCPBBRInfo: &TCPBBRInfo{
					BBRBW:         100,
					BBRMinRTT:     111,
					BBRPacingGain: 222,
					BBRCwndGain:   123,
				},
			},
		},
		{
			name: "TCPInfo Only",
			attrs: []syscall.NetlinkRouteAttr{
				{
					Attr: syscall.RtAttr{
						Len:  232,
						Type: INET_DIAG_INFO,
					},
					Value: tcpInfoData,
				},
			},
			expected: &InetDiagTCPInfoResp{
				TCPInfo: tcpInfo,
			},
		},
		{
			name: "TCPInfo + TCPBBR",
			attrs: []syscall.NetlinkRouteAttr{
				{
					Attr: syscall.RtAttr{
						Len:  232,
						Type: INET_DIAG_INFO,
					},
					Value: tcpInfoData,
				},
				{
					Attr: syscall.RtAttr{
						Len:  20,
						Type: INET_DIAG_BBRINFO,
					},
					Value: []byte{
						100, 0, 0, 0, 0, 0, 0, 0,
						111, 0, 0, 0,
						222, 0, 0, 0,
						123, 0, 0, 0,
					},
				},
			},
			expected: &InetDiagTCPInfoResp{
				TCPInfo: tcpInfo,
				TCPBBRInfo: &TCPBBRInfo{
					BBRBW:         100,
					BBRMinRTT:     111,
					BBRPacingGain: 222,
					BBRCwndGain:   123,
				},
			},
		},
		{
			name: "TCPBBR + TCPInfo (reverse)",
			attrs: []syscall.NetlinkRouteAttr{
				{
					Attr: syscall.RtAttr{
						Len:  20,
						Type: INET_DIAG_BBRINFO,
					},
					Value: []byte{
						100, 0, 0, 0, 0, 0, 0, 0,
						111, 0, 0, 0,
						222, 0, 0, 0,
						123, 0, 0, 0,
					},
				},
				{
					Attr: syscall.RtAttr{
						Len:  232,
						Type: INET_DIAG_INFO,
					},
					Value: tcpInfoData,
				},
			},
			expected: &InetDiagTCPInfoResp{
				TCPInfo: tcpInfo,
				TCPBBRInfo: &TCPBBRInfo{
					BBRBW:         100,
					BBRMinRTT:     111,
					BBRPacingGain: 222,
					BBRCwndGain:   123,
				},
			},
		},
	}

	for _, test := range tests {
		res, err := attrsToInetDiagTCPInfoResp(test.attrs, nil)
		if err != nil && !test.wantFail {
			t.Errorf("Unexpected failure for test %q", test.name)
			continue
		}

		if err == nil && test.wantFail {
			t.Errorf("Unexpected success for test %q", test.name)
			continue
		}

		if !reflect.DeepEqual(test.expected, res) {
			t.Errorf("Unexpected failure for test %q", test.name)
		}
	}
}
