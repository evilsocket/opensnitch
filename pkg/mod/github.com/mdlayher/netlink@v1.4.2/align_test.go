package netlink

import (
	"strconv"
	"testing"
)

func Test_nlmsgAlign(t *testing.T) {
	tests := []struct {
		in  int
		out int
	}{
		{
			in:  0,
			out: 0,
		},
		{
			in:  1,
			out: 4,
		},
		{
			in:  2,
			out: 4,
		},
		{
			in:  3,
			out: 4,
		},
		{
			in:  4,
			out: 4,
		},
		{
			in:  5,
			out: 8,
		},
		{
			in:  6,
			out: 8,
		},
		{
			in:  7,
			out: 8,
		},
		{
			in:  8,
			out: 8,
		},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.in), func(t *testing.T) {
			if want, got := tt.out, nlmsgAlign(tt.in); want != got {
				t.Fatalf("unexpected output:\n- want: %v\n-  got: %v", want, got)
			}
		})
	}
}

func Test_nlaAlign(t *testing.T) {
	tests := []struct {
		in  int
		out int
	}{
		{
			in:  0,
			out: 0,
		},
		{
			in:  1,
			out: 4,
		},
		{
			in:  2,
			out: 4,
		},
		{
			in:  3,
			out: 4,
		},
		{
			in:  4,
			out: 4,
		},
		{
			in:  5,
			out: 8,
		},
		{
			in:  6,
			out: 8,
		},
		{
			in:  7,
			out: 8,
		},
		{
			in:  8,
			out: 8,
		},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.in), func(t *testing.T) {
			if want, got := tt.out, nlaAlign(tt.in); want != got {
				t.Fatalf("unexpected output:\n- want: %v\n-  got: %v", want, got)
			}
		})
	}
}
