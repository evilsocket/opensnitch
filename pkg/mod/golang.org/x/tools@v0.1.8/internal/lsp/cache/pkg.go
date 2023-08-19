// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cache

import (
	"go/ast"
	"go/scanner"
	"go/types"

	"golang.org/x/mod/module"
	"golang.org/x/tools/internal/lsp/source"
	"golang.org/x/tools/internal/span"
	errors "golang.org/x/xerrors"
)

// pkg contains the type information needed by the source package.
type pkg struct {
	m               *Metadata
	mode            source.ParseMode
	goFiles         []*source.ParsedGoFile
	compiledGoFiles []*source.ParsedGoFile
	diagnostics     []*source.Diagnostic
	imports         map[PackagePath]*pkg
	version         *module.Version
	parseErrors     []scanner.ErrorList
	typeErrors      []types.Error
	types           *types.Package
	typesInfo       *types.Info
	typesSizes      types.Sizes
	hasFixedFiles   bool // if true, AST was sufficiently mangled that we should hide type errors
}

// Declare explicit types for files and directories to distinguish between the two.
type (
	fileURI         span.URI
	moduleLoadScope string
	viewLoadScope   span.URI
)

func (p *pkg) ID() string {
	return string(p.m.ID)
}

func (p *pkg) Name() string {
	return string(p.m.Name)
}

func (p *pkg) PkgPath() string {
	return string(p.m.PkgPath)
}

func (p *pkg) ParseMode() source.ParseMode {
	return p.mode
}

func (p *pkg) CompiledGoFiles() []*source.ParsedGoFile {
	return p.compiledGoFiles
}

func (p *pkg) File(uri span.URI) (*source.ParsedGoFile, error) {
	for _, cgf := range p.compiledGoFiles {
		if cgf.URI == uri {
			return cgf, nil
		}
	}
	for _, gf := range p.goFiles {
		if gf.URI == uri {
			return gf, nil
		}
	}
	return nil, errors.Errorf("no parsed file for %s in %v", uri, p.m.ID)
}

func (p *pkg) GetSyntax() []*ast.File {
	var syntax []*ast.File
	for _, pgf := range p.compiledGoFiles {
		syntax = append(syntax, pgf.File)
	}
	return syntax
}

func (p *pkg) GetTypes() *types.Package {
	return p.types
}

func (p *pkg) GetTypesInfo() *types.Info {
	return p.typesInfo
}

func (p *pkg) GetTypesSizes() types.Sizes {
	return p.typesSizes
}

func (p *pkg) IsIllTyped() bool {
	return p.types == nil || p.typesInfo == nil || p.typesSizes == nil
}

func (p *pkg) ForTest() string {
	return string(p.m.ForTest)
}

func (p *pkg) GetImport(pkgPath string) (source.Package, error) {
	if imp := p.imports[PackagePath(pkgPath)]; imp != nil {
		return imp, nil
	}
	// Don't return a nil pointer because that still satisfies the interface.
	return nil, errors.Errorf("no imported package for %s", pkgPath)
}

func (p *pkg) MissingDependencies() []string {
	// We don't invalidate metadata for import deletions, so check the package
	// imports via the *types.Package. Only use metadata if p.types is nil.
	if p.types == nil {
		var md []string
		for i := range p.m.MissingDeps {
			md = append(md, string(i))
		}
		return md
	}
	var md []string
	for _, pkg := range p.types.Imports() {
		if _, ok := p.m.MissingDeps[PackagePath(pkg.Path())]; ok {
			md = append(md, pkg.Path())
		}
	}
	return md
}

func (p *pkg) Imports() []source.Package {
	var result []source.Package
	for _, imp := range p.imports {
		result = append(result, imp)
	}
	return result
}

func (p *pkg) Version() *module.Version {
	return p.version
}

func (p *pkg) HasListOrParseErrors() bool {
	return len(p.m.Errors) != 0 || len(p.parseErrors) != 0
}

func (p *pkg) HasTypeErrors() bool {
	return len(p.typeErrors) != 0
}
