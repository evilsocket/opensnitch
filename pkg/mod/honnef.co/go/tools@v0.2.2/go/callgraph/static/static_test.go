// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//lint:file-ignore SA1019 go/callgraph's test suite is built around the deprecated go/loader. We'll leave fixing that to upstream.

package static_test

import (
	"fmt"
	"go/parser"
	"reflect"
	"sort"
	"testing"

	"honnef.co/go/tools/go/callgraph"
	"honnef.co/go/tools/go/callgraph/static"
	"honnef.co/go/tools/go/ir/irutil"

	"golang.org/x/tools/go/loader"
)

const input = `package P

type C int
func (C) f()

type I interface{f()}

func f() {
	p := func() {}
	g()
	p() // IR constant propagation => static

	if unknown {
		p = h
	}
	p() // dynamic

	C(0).f()
}

func g() {
	var i I = C(0)
	i.f()
}

func h()

var unknown bool
`

func TestStatic(t *testing.T) {
	conf := loader.Config{ParserMode: parser.ParseComments}
	f, err := conf.ParseFile("P.go", input)
	if err != nil {
		t.Fatal(err)
	}

	conf.CreateFromFiles("P", f)
	iprog, err := conf.Load()
	if err != nil {
		t.Fatal(err)
	}

	P := iprog.Created[0].Pkg

	prog := irutil.CreateProgram(iprog, 0)
	prog.Build()

	cg := static.CallGraph(prog)

	var edges []string
	callgraph.GraphVisitEdges(cg, func(e *callgraph.Edge) error {
		edges = append(edges, fmt.Sprintf("%s -> %s",
			e.Caller.Func.RelString(P),
			e.Callee.Func.RelString(P)))
		return nil
	})
	sort.Strings(edges)

	want := []string{
		"(*C).f -> (C).f",
		"f -> (C).f",
		"f -> f$1",
		"f -> g",
	}
	if !reflect.DeepEqual(edges, want) {
		t.Errorf("Got edges %v, want %v", edges, want)
	}
}
