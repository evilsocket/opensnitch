// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// No testdata on Android.

// +build !android

package irutil

import (
	"bytes"
	"fmt"
	"go/parser"
	"strings"
	"testing"

	"honnef.co/go/tools/go/ir"

	"golang.org/x/tools/go/loader"
)

func TestSwitches(t *testing.T) {
	conf := loader.Config{ParserMode: parser.ParseComments}
	f, err := conf.ParseFile("testdata/switches.go", nil)
	if err != nil {
		t.Error(err)
		return
	}

	conf.CreateFromFiles("main", f)
	iprog, err := conf.Load()
	if err != nil {
		t.Error(err)
		return
	}

	prog := CreateProgram(iprog, 0)
	mainPkg := prog.Package(iprog.Created[0].Pkg)
	mainPkg.Build()

	for _, mem := range mainPkg.Members {
		if fn, ok := mem.(*ir.Function); ok {
			if fn.Synthetic != 0 {
				continue // e.g. init()
			}
			// Each (multi-line) "switch" comment within
			// this function must match the printed form
			// of a ConstSwitch.
			var wantSwitches []string
			for _, c := range f.Comments {
				if fn.Source().Pos() <= c.Pos() && c.Pos() < fn.Source().End() {
					text := strings.TrimSpace(c.Text())
					if strings.HasPrefix(text, "switch ") {
						wantSwitches = append(wantSwitches, text)
					}
				}
			}

			switches := Switches(fn)
			if len(switches) != len(wantSwitches) {
				t.Errorf("in %s, found %d switches, want %d", fn, len(switches), len(wantSwitches))
			}
			for i, sw := range switches {
				got := sw.testString()
				if i >= len(wantSwitches) {
					continue
				}
				want := wantSwitches[i]
				if got != want {
					t.Errorf("in %s, found switch %d: got <<%s>>, want <<%s>>", fn, i, got, want)
				}
			}
		}
	}
}

func (sw *Switch) testString() string {
	// same as the actual String method, but use the second to last
	// instruction instead, to skip over all the phi and sigma nodes
	// that SSI produces.
	var buf bytes.Buffer
	if sw.ConstCases != nil {
		fmt.Fprintf(&buf, "switch %s {\n", sw.X.Name())
		for _, c := range sw.ConstCases {
			n := len(c.Body.Instrs) - 2
			if n < 0 {
				n = 0
			}
			fmt.Fprintf(&buf, "case %s: %s\n", c.Value.Name(), c.Body.Instrs[n])
		}
	} else {
		fmt.Fprintf(&buf, "switch %s.(type) {\n", sw.X.Name())
		for _, c := range sw.TypeCases {
			n := len(c.Body.Instrs) - 2
			if n < 0 {
				n = 0
			}
			fmt.Fprintf(&buf, "case %s %s: %s\n",
				c.Binding.Name(), c.Type, c.Body.Instrs[n])
		}
	}
	if sw.Default != nil {
		n := len(sw.Default.Instrs) - 2
		if n < 0 {
			n = 0
		}
		fmt.Fprintf(&buf, "default: %s\n", sw.Default.Instrs[n])
	}
	fmt.Fprintf(&buf, "}")
	return buf.String()
}
