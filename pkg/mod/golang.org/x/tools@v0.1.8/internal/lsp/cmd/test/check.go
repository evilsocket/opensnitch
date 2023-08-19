// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmdtest

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"golang.org/x/tools/internal/lsp/source"
	"golang.org/x/tools/internal/span"
)

func (r *runner) Diagnostics(t *testing.T, uri span.URI, want []*source.Diagnostic) {
	if len(want) == 1 && want[0].Message == "" {
		return
	}
	fname := uri.Filename()
	out, _ := r.runGoplsCmd(t, "check", fname)
	// parse got into a collection of reports
	got := map[string]struct{}{}
	for _, l := range strings.Split(out, "\n") {
		if len(l) == 0 {
			continue
		}
		// parse and reprint to normalize the span
		bits := strings.SplitN(l, ": ", 2)
		if len(bits) == 2 {
			spn := span.Parse(strings.TrimSpace(bits[0]))
			spn = span.New(spn.URI(), spn.Start(), span.Point{})
			data, err := ioutil.ReadFile(fname)
			if err != nil {
				t.Fatal(err)
			}
			converter := span.NewContentConverter(fname, data)
			s, err := spn.WithPosition(converter)
			if err != nil {
				t.Fatal(err)
			}
			l = fmt.Sprintf("%s: %s", s, strings.TrimSpace(bits[1]))
		}
		got[r.NormalizePrefix(l)] = struct{}{}
	}
	for _, diag := range want {
		expect := fmt.Sprintf("%v:%v:%v: %v", uri.Filename(), diag.Range.Start.Line+1, diag.Range.Start.Character+1, diag.Message)
		if diag.Range.Start.Character == 0 {
			expect = fmt.Sprintf("%v:%v: %v", uri.Filename(), diag.Range.Start.Line+1, diag.Message)
		}
		expect = r.NormalizePrefix(expect)
		_, found := got[expect]
		if !found {
			t.Errorf("missing diagnostic %q, %v", expect, got)
		} else {
			delete(got, expect)
		}
	}
	for extra := range got {
		t.Errorf("extra diagnostic %q", extra)
	}
}
