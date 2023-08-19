package ir_test

import (
	"testing"

	"golang.org/x/tools/go/packages"
	"honnef.co/go/tools/go/ir"
)

func BenchmarkSSA(b *testing.B) {
	cfg := &packages.Config{
		Mode:  packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "std")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prog := ir.NewProgram(pkgs[0].Fset, ir.GlobalDebug)
		seen := map[*packages.Package]struct{}{}
		var create func(pkg *packages.Package)
		create = func(pkg *packages.Package) {
			if _, ok := seen[pkg]; ok {
				return
			}
			seen[pkg] = struct{}{}
			prog.CreatePackage(pkg.Types, pkg.Syntax, pkg.TypesInfo, true)
			for _, imp := range pkg.Imports {
				create(imp)
			}
		}
		for _, pkg := range pkgs {
			create(pkg)
		}
		prog.Build()
	}
}
