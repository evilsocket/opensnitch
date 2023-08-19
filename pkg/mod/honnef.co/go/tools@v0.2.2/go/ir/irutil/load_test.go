// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package irutil_test

import (
	"bytes"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"

	"honnef.co/go/tools/go/ir/irutil"

	"golang.org/x/tools/go/packages"
)

const hello = `package main

import "fmt"

func main() {
	fmt.Println("Hello, world")
}
`

func TestBuildPackage(t *testing.T) {
	// There is a more substantial test of BuildPackage and the
	// IR program it builds in ../ir/builder_test.go.

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "hello.go", hello, 0)
	if err != nil {
		t.Fatal(err)
	}

	pkg := types.NewPackage("hello", "")
	irpkg, _, err := irutil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, pkg, []*ast.File{f}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Name() != "main" {
		t.Errorf("pkg.Name() = %s, want main", pkg.Name())
	}
	if irpkg.Func("main") == nil {
		irpkg.WriteTo(os.Stderr)
		t.Errorf("irpkg has no main function")
	}
}

func TestPackages(t *testing.T) {
	cfg := &packages.Config{Mode: packages.LoadSyntax}
	initial, err := packages.Load(cfg, "bytes")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(initial) > 0 {
		t.Fatal("there were errors")
	}

	prog, pkgs := irutil.Packages(initial, 0, nil)
	bytesNewBuffer := pkgs[0].Func("NewBuffer")
	bytesNewBuffer.Pkg.Build()

	// We'll dump the IR of bytes.NewBuffer because it is small and stable.
	out := new(bytes.Buffer)
	bytesNewBuffer.WriteTo(out)

	// For determinism, sanitize the location.
	location := prog.Fset.Position(bytesNewBuffer.Pos()).String()
	got := strings.Replace(out.String(), location, "$GOROOT/src/bytes/buffer.go:1", -1)

	want := `
# Name: bytes.NewBuffer
# Package: bytes
# Location: $GOROOT/src/bytes/buffer.go:1
func NewBuffer(buf []byte) *Buffer:
b0: # entry
	t1 = Parameter <[]byte> {buf}
	t2 = HeapAlloc <*Buffer>
	t3 = FieldAddr <*[]byte> [0] (buf) t2
	Store {[]byte} t3 t1
	Jump → b1

b1: ← b0 # exit
	Return t2

`[1:]
	if got != want {
		t.Errorf("bytes.NewBuffer IR = <<%s>>, want <<%s>>", got, want)
	}
}

func TestBuildPackage_MissingImport(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "bad.go", `package bad; import "missing"`, 0)
	if err != nil {
		t.Fatal(err)
	}

	pkg := types.NewPackage("bad", "")
	irpkg, _, err := irutil.BuildPackage(new(types.Config), fset, pkg, []*ast.File{f}, 0)
	if err == nil || irpkg != nil {
		t.Fatal("BuildPackage succeeded unexpectedly")
	}
}

func TestIssue28106(t *testing.T) {
	// In go1.10, go/packages loads all packages from source, not
	// export data, but does not type check function bodies of
	// imported packages. This test ensures that we do not attempt
	// to run the IR builder on functions without type information.
	cfg := &packages.Config{Mode: packages.LoadSyntax}
	pkgs, err := packages.Load(cfg, "runtime")
	if err != nil {
		t.Fatal(err)
	}
	prog, _ := irutil.Packages(pkgs, 0, nil)
	prog.Build() // no crash
}
