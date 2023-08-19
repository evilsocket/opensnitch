package netlink

import (
	"reflect"
	"testing"
)

var (
	tcpInfoData []byte
	tcpInfo     *TCPInfo
)

func init() {
	tcpInfoData = []byte{
		1, 0, 0, 0, 0, 7, 120, 1, 96, 216, 3, 0, 64,
		156, 0, 0, 120, 5, 0, 0, 64, 3, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 236, 216, 0, 0, 0, 0, 0, 0, 56, 216,
		0, 0, 144, 39, 0, 0, 220, 5, 0, 0, 88, 250,
		0, 0, 79, 190, 0, 0, 7, 5, 0, 0, 255, 255,
		255, 127, 10, 0, 0, 0, 168, 5, 0, 0, 3, 0, 0,
		0, 0, 0, 0, 0, 144, 56, 0, 0, 0, 0, 0, 0, 1, 197,
		8, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255,
		255, 255, 157, 42, 0, 0, 0, 0, 0, 0, 148, 26, 0,
		0, 0, 0, 0, 0, 181, 0, 0, 0, 95, 0, 0, 0, 0, 0, 0,
		0, 93, 180, 0, 0, 61, 0, 0, 0, 89, 0, 0, 0, 47, 216,
		1, 0, 0, 0, 0, 0, 32, 65, 23, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 90, 0, 0,
		0, 0, 0, 0, 0, 156, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 195, 1, 0,
	}
	tcpInfo = &TCPInfo{
		State:           1,
		Options:         7,
		Snd_wscale:      7,
		Rcv_wscale:      8,
		Rto:             252000,
		Ato:             40000,
		Snd_mss:         1400,
		Rcv_mss:         832,
		Last_data_sent:  55532,
		Last_data_recv:  55352,
		Last_ack_recv:   10128,
		Pmtu:            1500,
		Rcv_ssthresh:    64088,
		Rtt:             48719,
		Rttvar:          1287,
		Snd_ssthresh:    2147483647,
		Snd_cwnd:        10,
		Advmss:          1448,
		Reordering:      3,
		Rcv_space:       14480,
		Pacing_rate:     574721,
		Max_pacing_rate: 18446744073709551615,
		Bytes_acked:     10909,
		Bytes_received:  6804,
		Segs_out:        181,
		Segs_in:         95,
		Min_rtt:         46173,
		Data_segs_in:    61,
		Data_segs_out:   89,
		Delivery_rate:   120879,
		Busy_time:       1524000,
		Delivered:       90,
		Bytes_sent:      10908,
		Snd_wnd:         115456,
	}
}

func TestTCPInfoDeserialize(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *TCPInfo
		wantFail bool
	}{
		{
			name:     "Valid data",
			input:    tcpInfoData,
			expected: tcpInfo,
		},
	}

	for _, test := range tests {
		tcpbbr := &TCPInfo{}
		err := tcpbbr.deserialize(test.input)
		if err != nil && !test.wantFail {
			t.Errorf("Unexpected failure for test %q", test.name)
			continue
		}

		if err != nil && test.wantFail {
			continue
		}

		if !reflect.DeepEqual(test.expected, tcpbbr) {
			t.Errorf("Unexpected failure for test %q", test.name)
		}
	}
}

func TestTCPBBRInfoDeserialize(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *TCPBBRInfo
		wantFail bool
	}{
		{
			name: "Valid data",
			input: []byte{
				100, 0, 0, 0, 0, 0, 0, 0,
				111, 0, 0, 0,
				222, 0, 0, 0,
				123, 0, 0, 0,
			},
			expected: &TCPBBRInfo{
				BBRBW:         100,
				BBRMinRTT:     111,
				BBRPacingGain: 222,
				BBRCwndGain:   123,
			},
		},
		{
			name: "Invalid length",
			input: []byte{
				100, 0, 0, 0, 0, 0, 0, 0,
				111, 0, 0, 0,
				222, 0, 0, 0,
				123, 0, 0,
			},
			wantFail: true,
		},
	}

	for _, test := range tests {
		tcpbbr := &TCPBBRInfo{}
		err := tcpbbr.deserialize(test.input)
		if err != nil && !test.wantFail {
			t.Errorf("Unexpected failure for test %q", test.name)
			continue
		}

		if err != nil && test.wantFail {
			continue
		}

		if !reflect.DeepEqual(test.expected, tcpbbr) {
			t.Errorf("Unexpected failure for test %q", test.name)
		}
	}
}
