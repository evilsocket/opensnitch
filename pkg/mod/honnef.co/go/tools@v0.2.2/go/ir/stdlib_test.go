// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//lint:file-ignore SA1019 go/ssa's test suite is built around the deprecated go/loader. We'll leave fixing that to upstream.

// Incomplete source tree on Android.

// +build !android

package ir_test

// This file runs the IR builder in sanity-checking mode on all
// packages beneath $GOROOT and prints some summary information.
//
// Run with "go test -cpu=8 to" set GOMAXPROCS.

import (
	"go/ast"
	"go/token"
	"runtime"
	"testing"
	"time"

	"honnef.co/go/tools/go/ir"
	"honnef.co/go/tools/go/ir/irutil"

	"golang.org/x/tools/go/packages"
)

func bytesAllocated() uint64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.TotalAlloc
}

func TestStdlib(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode; too slow (golang.org/issue/14113)")
	}

	var (
		numFuncs  int
		numInstrs int

		dLoad   time.Duration
		dCreate time.Duration
		dBuild  time.Duration

		allocLoad  uint64
		allocBuild uint64
	)

	// Load, parse and type-check the program.
	t0 := time.Now()
	alloc0 := bytesAllocated()

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedTypesSizes,
	}
	pkgs, err := packages.Load(cfg, "std")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	allocLoad = bytesAllocated() - alloc0
	dLoad = time.Since(t0)

	alloc0 = bytesAllocated()
	for _, pkg := range pkgs {
		if len(pkg.Errors) != 0 {
			t.Fatalf("Load failed: %v", pkg.Errors)
		}

		var mode ir.BuilderMode
		// Comment out these lines during benchmarking.  Approx IR build costs are noted.
		mode |= ir.SanityCheckFunctions // + 2% space, + 4% time
		mode |= ir.GlobalDebug          // +30% space, +18% time
		prog := ir.NewProgram(pkg.Fset, mode)

		t0 := time.Now()
		var irpkg *ir.Package
		for _, pkg2 := range pkgs {
			r := prog.CreatePackage(pkg2.Types, pkg2.Syntax, pkg2.TypesInfo, true)
			if pkg2 == pkg {
				irpkg = r
			}
		}
		dCreate += time.Since(t0)

		t0 = time.Now()
		irpkg.Build()
		dBuild += time.Since(t0)

		allFuncs := irutil.AllFunctions(prog)
		numFuncs += len(allFuncs)

		// Check that all non-synthetic functions have distinct names.
		// Synthetic wrappers for exported methods should be distinct too,
		// except for unexported ones (explained at (*Function).RelString).
		byName := make(map[string]*ir.Function)
		for fn := range allFuncs {
			if fn.Synthetic == 0 || ast.IsExported(fn.Name()) {
				str := fn.String()
				prev := byName[str]
				byName[str] = fn
				if prev != nil {
					t.Errorf("%s: duplicate function named %s",
						prog.Fset.Position(fn.Pos()), str)
					t.Errorf("%s:   (previously defined here)",
						prog.Fset.Position(prev.Pos()))
				}
			}
		}

		// Dump some statistics.
		var numInstrs int
		for fn := range allFuncs {
			for _, b := range fn.Blocks {
				numInstrs += len(b.Instrs)
			}
		}
	}
	allocBuild = bytesAllocated() - alloc0

	// determine line count
	var lineCount int
	pkgs[0].Fset.Iterate(func(f *token.File) bool {
		lineCount += f.LineCount()
		return true
	})

	// NB: when benchmarking, don't forget to clear the debug +
	// sanity builder flags for better performance.

	t.Log("GOMAXPROCS:           ", runtime.GOMAXPROCS(0))
	t.Log("#Source lines:        ", lineCount)
	t.Log("Load/parse/typecheck: ", dLoad)
	t.Log("IR create:           ", dCreate)
	t.Log("IR build:            ", dBuild)

	// IR stats:
	t.Log("#Packages:            ", len(pkgs))
	t.Log("#Functions:           ", numFuncs)
	t.Log("#Instructions:        ", numInstrs)
	t.Log("#MB AST+types:        ", allocLoad/1e6)
	t.Log("#MB IR:              ", allocBuild/1e6)
}
