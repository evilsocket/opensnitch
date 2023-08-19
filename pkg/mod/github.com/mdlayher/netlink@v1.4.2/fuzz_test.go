//go:build gofuzz
// +build gofuzz

package netlink

import "testing"

func Test_fuzz(t *testing.T) {
	tests := []struct {
		name string
		s    string
	}{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = fuzz([]byte(tt.s))
		})
	}
}
