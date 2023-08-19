// Copyright 2017 Kinvolk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build linux

package elf

import (
	"testing"
)

func TestValidateMapPath(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{
			input:    "/sys/fs/bpf/good/path",
			expected: true,
		},
		{
			input:    "/sys/fs/bpf/../../bad/path",
			expected: false,
		},
		{
			input:    "/sys/fs/bpf/./bad/path",
			expected: false,
		},
		{
			input:    "/bad/path",
			expected: false,
		},
	}

	for i, tt := range tests {
		if isValid := validateMapPath(tt.input); isValid != tt.expected {
			t.Fatalf("test %d (%s) expected %t but got %t", i, tt.input, tt.expected, isValid)
		}
	}
}
