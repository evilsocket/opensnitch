// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xerrors

import "testing"

func TestParsePrintfVerb(t *testing.T) {
	for _, test := range []struct {
		in       string
		wantSize int
		wantW    bool
	}{
		{"", 0, false},
		{"%", 1, false},
		{"%3.1", 4, false},
		{"%w", 2, true},
		{"%v", 2, false},
		{"%3.*[4]d", 8, false},
	} {
		gotSize, gotW := parsePrintfVerb(test.in)
		if gotSize != test.wantSize || gotW != test.wantW {
			t.Errorf("parsePrintfVerb(%q) = (%d, %t), want (%d, %t)",
				test.in, gotSize, gotW, test.wantSize, test.wantW)
		}
	}
}

func TestParsePercentW(t *testing.T) {
	for _, test := range []struct {
		in         string
		wantIdx    int
		wantFormat string
		wantOK     bool
	}{
		{"", -1, "", true},
		{"%", -1, "%", true},
		{"%w", 0, "%v", true},
		{"%w%w", 0, "%v%v", false},
		{"%3.2s %+q %% %w %#v", 2, "%3.2s %+q %% %v %#v", true},
		{"%3.2s %w %% %w %#v", 1, "%3.2s %v %% %v %#v", false},
	} {
		gotIdx, gotFormat, gotOK := parsePercentW(test.in)
		if gotIdx != test.wantIdx || gotFormat != test.wantFormat || gotOK != test.wantOK {
			t.Errorf("parsePercentW(%q) = (%d, %q, %t), want (%d, %q, %t)",
				test.in, gotIdx, gotFormat, gotOK, test.wantIdx, test.wantFormat, test.wantOK)

		}
	}
}
