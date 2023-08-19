// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//lint:file-ignore SA1019 go/ssa's test suite is built around the deprecated go/loader. We'll leave fixing that to upstream.

package ir_test

import (
	"bytes"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"reflect"
	"sort"
	"testing"

	"honnef.co/go/tools/go/ir"
	"honnef.co/go/tools/go/ir/irutil"

	"golang.org/x/tools/go/loader"
)

func isEmpty(f *ir.Function) bool { return f.Blocks == nil }

// Tests that programs partially loaded from gc object files contain
// functions with no code for the external portions, but are otherwise ok.
func TestBuildPackage(t *testing.T) {
	input := `
package main

import (
	"bytes"
	"io"
	"testing"
)

func main() {
	var t testing.T
	t.Parallel()    // static call to external declared method
	t.Fail()        // static call to promoted external declared method
	testing.Short() // static call to external package-level function

	var w io.Writer = new(bytes.Buffer)
	w.Write(nil)    // interface invoke of external declared method
}
`

	// Parse the file.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "input.go", input, 0)
	if err != nil {
		t.Error(err)
		return
	}

	// Build an IR program from the parsed file.
	// Load its dependencies from gc binary export data.
	mainPkg, _, err := irutil.BuildPackage(&types.Config{Importer: importer.Default()}, fset,
		types.NewPackage("main", ""), []*ast.File{f}, ir.SanityCheckFunctions)
	if err != nil {
		t.Error(err)
		return
	}

	// The main package, its direct and indirect dependencies are loaded.
	deps := []string{
		// directly imported dependencies:
		"bytes", "io", "testing",
		// indirect dependencies mentioned by
		// the direct imports' export data
		"sync", "unicode", "time",
	}

	prog := mainPkg.Prog
	all := prog.AllPackages()
	if len(all) <= len(deps) {
		t.Errorf("unexpected set of loaded packages: %q", all)
	}
	for _, path := range deps {
		pkg := prog.ImportedPackage(path)
		if pkg == nil {
			t.Errorf("package not loaded: %q", path)
			continue
		}

		// External packages should have no function bodies (except for wrappers).
		isExt := pkg != mainPkg

		// init()
		if isExt && !isEmpty(pkg.Func("init")) {
			t.Errorf("external package %s has non-empty init", pkg)
		} else if !isExt && isEmpty(pkg.Func("init")) {
			t.Errorf("main package %s has empty init", pkg)
		}

		for _, mem := range pkg.Members {
			switch mem := mem.(type) {
			case *ir.Function:
				// Functions at package level.
				if isExt && !isEmpty(mem) {
					t.Errorf("external function %s is non-empty", mem)
				} else if !isExt && isEmpty(mem) {
					t.Errorf("function %s is empty", mem)
				}

			case *ir.Type:
				// Methods of named types T.
				// (In this test, all exported methods belong to *T not T.)
				if !isExt {
					t.Fatalf("unexpected name type in main package: %s", mem)
				}
				mset := prog.MethodSets.MethodSet(types.NewPointer(mem.Type()))
				for i, n := 0, mset.Len(); i < n; i++ {
					m := prog.MethodValue(mset.At(i))
					// For external types, only synthetic wrappers have code.
					expExt := m.Synthetic != ir.SyntheticWrapper
					if expExt && !isEmpty(m) {
						t.Errorf("external method %s is non-empty: %s",
							m, m.Synthetic)
					} else if !expExt && isEmpty(m) {
						t.Errorf("method function %s is empty: %s",
							m, m.Synthetic)
					}
				}
			}
		}
	}

	expectedCallee := []string{
		"(*testing.T).Parallel",
		"(*testing.common).Fail",
		"testing.Short",
		"N/A",
	}
	callNum := 0
	for _, b := range mainPkg.Func("main").Blocks {
		for _, instr := range b.Instrs {
			switch instr := instr.(type) {
			case ir.CallInstruction:
				call := instr.Common()
				if want := expectedCallee[callNum]; want != "N/A" {
					got := call.StaticCallee().String()
					if want != got {
						t.Errorf("call #%d from main.main: got callee %s, want %s",
							callNum, got, want)
					}
				}
				callNum++
			}
		}
	}
	if callNum != 4 {
		t.Errorf("in main.main: got %d calls, want %d", callNum, 4)
	}
}

// TestRuntimeTypes tests that (*Program).RuntimeTypes() includes all necessary types.
func TestRuntimeTypes(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		// An exported package-level type is needed.
		{`package A; type T struct{}; func (T) f() {}`,
			[]string{"*p.T", "p.T"},
		},
		// An unexported package-level type is not needed.
		{`package B; type t struct{}; func (t) f() {}`,
			nil,
		},
		// Subcomponents of type of exported package-level var are needed.
		{`package C; import "bytes"; var V struct {*bytes.Buffer}`,
			[]string{"*bytes.Buffer", "*struct{*bytes.Buffer}", "struct{*bytes.Buffer}"},
		},
		// Subcomponents of type of unexported package-level var are not needed.
		{`package D; import "bytes"; var v struct {*bytes.Buffer}`,
			nil,
		},
		// Subcomponents of type of exported package-level function are needed.
		{`package E; import "bytes"; func F(struct {*bytes.Buffer}) {}`,
			[]string{"*bytes.Buffer", "struct{*bytes.Buffer}"},
		},
		// Subcomponents of type of unexported package-level function are not needed.
		{`package F; import "bytes"; func f(struct {*bytes.Buffer}) {}`,
			nil,
		},
		// Subcomponents of type of exported method of uninstantiated unexported type are not needed.
		{`package G; import "bytes"; type x struct{}; func (x) G(struct {*bytes.Buffer}) {}; var v x`,
			nil,
		},
		// ...unless used by MakeInterface.
		{`package G2; import "bytes"; type x struct{}; func (x) G(struct {*bytes.Buffer}) {}; var v interface{} = x{}`,
			[]string{"*bytes.Buffer", "*p.x", "p.x", "struct{*bytes.Buffer}"},
		},
		// Subcomponents of type of unexported method are not needed.
		{`package I; import "bytes"; type X struct{}; func (X) G(struct {*bytes.Buffer}) {}`,
			[]string{"*bytes.Buffer", "*p.X", "p.X", "struct{*bytes.Buffer}"},
		},
		// Local types aren't needed.
		{`package J; import "bytes"; func f() { type T struct {*bytes.Buffer}; var t T; _ = t }`,
			nil,
		},
		// ...unless used by MakeInterface.
		{`package K; import "bytes"; func f() { type T struct {*bytes.Buffer}; _ = interface{}(T{}) }`,
			[]string{"*bytes.Buffer", "*p.T", "p.T"},
		},
		// Types used as operand of MakeInterface are needed.
		{`package L; import "bytes"; func f() { _ = interface{}(struct{*bytes.Buffer}{}) }`,
			[]string{"*bytes.Buffer", "struct{*bytes.Buffer}"},
		},
		// MakeInterface is optimized away when storing to a blank.
		{`package M; import "bytes"; var _ interface{} = struct{*bytes.Buffer}{}`,
			nil,
		},
	}
	for _, test := range tests {
		// Parse the file.
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "input.go", test.input, 0)
		if err != nil {
			t.Errorf("test %q: %s", test.input[:15], err)
			continue
		}

		// Create a single-file main package.
		// Load dependencies from gc binary export data.
		irpkg, _, err := irutil.BuildPackage(&types.Config{Importer: importer.Default()}, fset,
			types.NewPackage("p", ""), []*ast.File{f}, ir.SanityCheckFunctions)
		if err != nil {
			t.Errorf("test %q: %s", test.input[:15], err)
			continue
		}

		var typstrs []string
		for _, T := range irpkg.Prog.RuntimeTypes() {
			typstrs = append(typstrs, T.String())
		}
		sort.Strings(typstrs)

		if !reflect.DeepEqual(typstrs, test.want) {
			t.Errorf("test 'package %s': got %q, want %q",
				f.Name.Name, typstrs, test.want)
		}
	}
}

// TestInit tests that synthesized init functions are correctly formed.
func TestInit(t *testing.T) {
	tests := []struct {
		mode        ir.BuilderMode
		input, want string
	}{
		{0, `package A; import _ "errors"; var i int = 42`,
			`# Name: A.init
# Package: A
# Synthetic: package initializer
func init():
b0: # entry
	t1 = Const <bool> {true}
	t2 = Const <int> {42}
	t3 = Load <bool> init$guard
	If t3 → b1 b2

b1: ← b0 b2 # exit
	Return

b2: ← b0 # init.start
	Store {bool} init$guard t1
	t7 = Call <()> errors.init
	Store {int} i t2
	Jump → b1

`},
	}
	for _, test := range tests {
		// Create a single-file main package.
		var conf loader.Config
		f, err := conf.ParseFile("<input>", test.input)
		if err != nil {
			t.Errorf("test %q: %s", test.input[:15], err)
			continue
		}
		conf.CreateFromFiles(f.Name.Name, f)

		lprog, err := conf.Load()
		if err != nil {
			t.Errorf("test 'package %s': Load: %s", f.Name.Name, err)
			continue
		}
		prog := irutil.CreateProgram(lprog, test.mode)
		mainPkg := prog.Package(lprog.Created[0].Pkg)
		prog.Build()
		initFunc := mainPkg.Func("init")
		if initFunc == nil {
			t.Errorf("test 'package %s': no init function", f.Name.Name)
			continue
		}

		var initbuf bytes.Buffer
		_, err = initFunc.WriteTo(&initbuf)
		if err != nil {
			t.Errorf("test 'package %s': WriteTo: %s", f.Name.Name, err)
			continue
		}

		if initbuf.String() != test.want {
			t.Errorf("test 'package %s': got %s, want %s", f.Name.Name, initbuf.String(), test.want)
		}
	}
}

// TestSyntheticFuncs checks that the expected synthetic functions are
// created, reachable, and not duplicated.
func TestSyntheticFuncs(t *testing.T) {
	const input = `package P
type T int
func (T) f() int
func (*T) g() int
var (
	// thunks
	a = T.f
	b = T.f
	c = (struct{T}).f
	d = (struct{T}).f
	e = (*T).g
	f = (*T).g
	g = (struct{*T}).g
	h = (struct{*T}).g

	// bounds
	i = T(0).f
	j = T(0).f
	k = new(T).g
	l = new(T).g

	// wrappers
	m interface{} = struct{T}{}
	n interface{} = struct{T}{}
	o interface{} = struct{*T}{}
	p interface{} = struct{*T}{}
	q interface{} = new(struct{T})
	r interface{} = new(struct{T})
	s interface{} = new(struct{*T})
	t interface{} = new(struct{*T})
)
`
	// Parse
	var conf loader.Config
	f, err := conf.ParseFile("<input>", input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	conf.CreateFromFiles(f.Name.Name, f)

	// Load
	lprog, err := conf.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Create and build IR
	prog := irutil.CreateProgram(lprog, 0)
	prog.Build()

	// Enumerate reachable synthetic functions
	want := map[string]ir.Synthetic{
		"(*P.T).g$bound": ir.SyntheticBound,
		"(P.T).f$bound":  ir.SyntheticBound,

		"(*P.T).g$thunk":         ir.SyntheticThunk,
		"(P.T).f$thunk":          ir.SyntheticThunk,
		"(struct{*P.T}).g$thunk": ir.SyntheticThunk,
		"(struct{P.T}).f$thunk":  ir.SyntheticThunk,

		"(*P.T).f":          ir.SyntheticWrapper,
		"(*struct{*P.T}).f": ir.SyntheticWrapper,
		"(*struct{*P.T}).g": ir.SyntheticWrapper,
		"(*struct{P.T}).f":  ir.SyntheticWrapper,
		"(*struct{P.T}).g":  ir.SyntheticWrapper,
		"(struct{*P.T}).f":  ir.SyntheticWrapper,
		"(struct{*P.T}).g":  ir.SyntheticWrapper,
		"(struct{P.T}).f":   ir.SyntheticWrapper,

		"P.init": ir.SyntheticPackageInitializer,
	}
	for fn := range irutil.AllFunctions(prog) {
		if fn.Synthetic == 0 {
			continue
		}
		name := fn.String()
		wantDescr, ok := want[name]
		if !ok {
			t.Errorf("got unexpected/duplicate func: %q: %q", name, fn.Synthetic)
			continue
		}
		delete(want, name)

		if wantDescr != fn.Synthetic {
			t.Errorf("(%s).Synthetic = %q, want %q", name, fn.Synthetic, wantDescr)
		}
	}
	for fn, descr := range want {
		t.Errorf("want func: %q: %q", fn, descr)
	}
}

// TestPhiElimination ensures that dead phis, including those that
// participate in a cycle, are properly eliminated.
func TestPhiElimination(t *testing.T) {
	const input = `
package p

func f() error

func g(slice []int) {
	for {
		for range slice {
			// e should not be lifted to a dead φ-node.
			e := f()
			h(e)
		}
	}
}

func h(error)
`
	// The IR code for this function should look something like this:
	// 0:
	//         jump 1
	// 1:
	//         t0 = len(slice)
	//         jump 2
	// 2:
	//         t1 = phi [1: -1:int, 3: t2]
	//         t2 = t1 + 1:int
	//         t3 = t2 < t0
	//         if t3 goto 3 else 1
	// 3:
	//         t4 = f()
	//         t5 = h(t4)
	//         jump 2
	//
	// But earlier versions of the IR construction algorithm would
	// additionally generate this cycle of dead phis:
	//
	// 1:
	//         t7 = phi [0: nil:error, 2: t8] #e
	//         ...
	// 2:
	//         t8 = phi [1: t7, 3: t4] #e
	//         ...

	// Parse
	var conf loader.Config
	f, err := conf.ParseFile("<input>", input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	conf.CreateFromFiles("p", f)

	// Load
	lprog, err := conf.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Create and build IR
	prog := irutil.CreateProgram(lprog, 0)
	p := prog.Package(lprog.Package("p").Pkg)
	p.Build()
	g := p.Func("g")

	phis := 0
	for _, b := range g.Blocks {
		for _, instr := range b.Instrs {
			if _, ok := instr.(*ir.Phi); ok {
				phis++
			}
		}
	}
	if expected := 3; phis != expected {
		g.WriteTo(os.Stderr)
		t.Errorf("expected %d Phi nodes (for the range index), got %d", expected, phis)
	}
}
