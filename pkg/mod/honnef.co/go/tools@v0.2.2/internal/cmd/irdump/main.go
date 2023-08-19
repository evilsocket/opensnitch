// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// irdump: a tool for displaying the IR form of Go programs.
package main

import (
	"flag"
	"fmt"
	"go/build"
	"os"
	"runtime/pprof"

	"honnef.co/go/tools/go/ir"
	"honnef.co/go/tools/go/ir/irutil"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
)

// flags
var (
	mode       = ir.BuilderMode(ir.PrintPackages | ir.PrintFunctions)
	testFlag   = flag.Bool("test", false, "include implicit test packages and executables")
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	dot        bool
	html       string
)

func init() {
	flag.Var(&mode, "build", ir.BuilderModeDoc)
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
	flag.BoolVar(&dot, "dot", false, "Print Graphviz dot of CFG")
	flag.StringVar(&html, "html", "", "Print HTML for 'function'")
}

const usage = `IR builder.
Usage: irdump [-build=[DBCSNFL]] [-test] [-arg=...] package...
Use -help flag to display options.

Examples:
% irdump -build=F hello.go              # dump IR form of a single package
% irdump -build=F -test fmt             # dump IR form of a package and its tests
`

func main() {
	if err := doMain(); err != nil {
		fmt.Fprintf(os.Stderr, "irdump: %s\n", err)
		os.Exit(1)
	}
}

func doMain() error {
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo,
		Tests: *testFlag,
	}

	// Profiling support.
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// Load, parse and type-check the initial packages.
	initial, err := packages.Load(cfg, flag.Args()...)
	if err != nil {
		return err
	}
	if len(initial) == 0 {
		return fmt.Errorf("no packages")
	}
	if packages.PrintErrors(initial) > 0 {
		return fmt.Errorf("packages contain errors")
	}

	// Create IR-form program representation.
	_, pkgs := irutil.Packages(initial, mode, &irutil.Options{PrintFunc: html})

	for i, p := range pkgs {
		if p == nil {
			return fmt.Errorf("cannot build IR for package %s", initial[i])
		}
	}

	// Build and display only the initial packages
	// (and synthetic wrappers).
	for _, p := range pkgs {
		p.Build()
	}

	if dot {
		for _, p := range pkgs {
			for _, m := range p.Members {
				if fn, ok := m.(*ir.Function); ok {
					fmt.Println("digraph{")
					fmt.Printf("label = %q;\n", fn.Name())
					for _, b := range fn.Blocks {
						fmt.Printf("n%d [label=\"%d: %s\"]\n", b.Index, b.Index, b.Comment)
						for _, succ := range b.Succs {
							fmt.Printf("n%d -> n%d\n", b.Index, succ.Index)
						}
					}
					fmt.Println("}")
				}
			}
		}
	}
	return nil
}
