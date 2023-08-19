// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package source

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strconv"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/internal/event"
	"golang.org/x/tools/internal/lsp/protocol"
	"golang.org/x/tools/internal/span"
	"golang.org/x/tools/internal/typeparams"
	errors "golang.org/x/xerrors"
)

// IdentifierInfo holds information about an identifier in Go source.
type IdentifierInfo struct {
	Name     string
	Snapshot Snapshot
	MappedRange

	Type struct {
		MappedRange
		Object types.Object
	}

	Inferred *types.Signature

	Declaration Declaration

	ident *ast.Ident

	// enclosing is an expression used to determine the link anchor for an
	// identifier. If it's a named type, it should be exported.
	enclosing types.Type

	pkg Package
	qf  types.Qualifier
}

func (i *IdentifierInfo) IsImport() bool {
	_, ok := i.Declaration.node.(*ast.ImportSpec)
	return ok
}

type Declaration struct {
	MappedRange []MappedRange

	// The typechecked node.
	node ast.Node

	// Optional: the fully parsed node, to be used for formatting in cases where
	// node has missing information. This could be the case when node was parsed
	// in ParseExported mode.
	fullDecl ast.Decl

	// The typechecked object.
	obj types.Object

	// typeSwitchImplicit indicates that the declaration is in an implicit
	// type switch. Its type is the type of the variable on the right-hand
	// side of the type switch.
	typeSwitchImplicit types.Type
}

// Identifier returns identifier information for a position
// in a file, accounting for a potentially incomplete selector.
func Identifier(ctx context.Context, snapshot Snapshot, fh FileHandle, pos protocol.Position) (*IdentifierInfo, error) {
	ctx, done := event.Start(ctx, "source.Identifier")
	defer done()

	pkgs, err := snapshot.PackagesForFile(ctx, fh.URI(), TypecheckAll, false)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages for file %v", fh.URI())
	}
	sort.Slice(pkgs, func(i, j int) bool {
		// Prefer packages with a more complete parse mode.
		if pkgs[i].ParseMode() != pkgs[j].ParseMode() {
			return pkgs[i].ParseMode() > pkgs[j].ParseMode()
		}
		return len(pkgs[i].CompiledGoFiles()) < len(pkgs[j].CompiledGoFiles())
	})
	var findErr error
	for _, pkg := range pkgs {
		pgf, err := pkg.File(fh.URI())
		if err != nil {
			return nil, err
		}
		spn, err := pgf.Mapper.PointSpan(pos)
		if err != nil {
			return nil, err
		}
		rng, err := spn.Range(pgf.Mapper.Converter)
		if err != nil {
			return nil, err
		}
		var ident *IdentifierInfo
		ident, findErr = findIdentifier(ctx, snapshot, pkg, pgf, rng.Start)
		if findErr == nil {
			return ident, nil
		}
	}
	return nil, findErr
}

// ErrNoIdentFound is error returned when no identifer is found at a particular position
var ErrNoIdentFound = errors.New("no identifier found")

func findIdentifier(ctx context.Context, snapshot Snapshot, pkg Package, pgf *ParsedGoFile, pos token.Pos) (*IdentifierInfo, error) {
	file := pgf.File
	// Handle import specs separately, as there is no formal position for a
	// package declaration.
	if result, err := importSpec(snapshot, pkg, file, pos); result != nil || err != nil {
		return result, err
	}
	path := pathEnclosingObjNode(file, pos)
	if path == nil {
		return nil, ErrNoIdentFound
	}

	qf := Qualifier(file, pkg.GetTypes(), pkg.GetTypesInfo())

	ident, _ := path[0].(*ast.Ident)
	if ident == nil {
		return nil, ErrNoIdentFound
	}
	// Special case for package declarations, since they have no
	// corresponding types.Object.
	if ident == file.Name {
		rng, err := posToMappedRange(snapshot, pkg, file.Name.Pos(), file.Name.End())
		if err != nil {
			return nil, err
		}
		var declAST *ast.File
		for _, pgf := range pkg.CompiledGoFiles() {
			if pgf.File.Doc != nil {
				declAST = pgf.File
			}
		}
		// If there's no package documentation, just use current file.
		if declAST == nil {
			declAST = file
		}
		declRng, err := posToMappedRange(snapshot, pkg, declAST.Name.Pos(), declAST.Name.End())
		if err != nil {
			return nil, err
		}
		return &IdentifierInfo{
			Name:        file.Name.Name,
			ident:       file.Name,
			MappedRange: rng,
			pkg:         pkg,
			qf:          qf,
			Snapshot:    snapshot,
			Declaration: Declaration{
				node:        declAST.Name,
				MappedRange: []MappedRange{declRng},
			},
		}, nil
	}

	result := &IdentifierInfo{
		Snapshot:  snapshot,
		qf:        qf,
		pkg:       pkg,
		ident:     ident,
		enclosing: searchForEnclosing(pkg.GetTypesInfo(), path),
	}

	result.Name = result.ident.Name
	var err error
	if result.MappedRange, err = posToMappedRange(snapshot, pkg, result.ident.Pos(), result.ident.End()); err != nil {
		return nil, err
	}

	result.Declaration.obj = pkg.GetTypesInfo().ObjectOf(result.ident)
	if result.Declaration.obj == nil {
		// If there was no types.Object for the declaration, there might be an
		// implicit local variable declaration in a type switch.
		if objs, typ := typeSwitchImplicits(pkg, path); len(objs) > 0 {
			// There is no types.Object for the declaration of an implicit local variable,
			// but all of the types.Objects associated with the usages of this variable can be
			// used to connect it back to the declaration.
			// Preserve the first of these objects and treat it as if it were the declaring object.
			result.Declaration.obj = objs[0]
			result.Declaration.typeSwitchImplicit = typ
		} else {
			// Probably a type error.
			return nil, errors.Errorf("%w for ident %v", errNoObjectFound, result.Name)
		}
	}

	// Handle builtins separately.
	if result.Declaration.obj.Parent() == types.Universe {
		builtin, err := snapshot.BuiltinFile(ctx)
		if err != nil {
			return nil, err
		}
		builtinObj := builtin.File.Scope.Lookup(result.Name)
		if builtinObj == nil {
			return nil, fmt.Errorf("no builtin object for %s", result.Name)
		}
		decl, ok := builtinObj.Decl.(ast.Node)
		if !ok {
			return nil, errors.Errorf("no declaration for %s", result.Name)
		}
		result.Declaration.node = decl

		// The builtin package isn't in the dependency graph, so the usual
		// utilities won't work here.
		rng := NewMappedRange(snapshot.FileSet(), builtin.Mapper, decl.Pos(), decl.Pos()+token.Pos(len(result.Name)))
		result.Declaration.MappedRange = append(result.Declaration.MappedRange, rng)
		return result, nil
	}

	// (error).Error is a special case of builtin. Lots of checks to confirm
	// that this is the builtin Error.
	if obj := result.Declaration.obj; obj.Parent() == nil && obj.Pkg() == nil && obj.Name() == "Error" {
		if _, ok := obj.Type().(*types.Signature); ok {
			builtin, err := snapshot.BuiltinFile(ctx)
			if err != nil {
				return nil, err
			}
			// Look up "error" and then navigate to its only method.
			// The Error method does not appear in the builtin package's scope.log.Pri
			const errorName = "error"
			builtinObj := builtin.File.Scope.Lookup(errorName)
			if builtinObj == nil {
				return nil, fmt.Errorf("no builtin object for %s", errorName)
			}
			decl, ok := builtinObj.Decl.(ast.Node)
			if !ok {
				return nil, errors.Errorf("no declaration for %s", errorName)
			}
			spec, ok := decl.(*ast.TypeSpec)
			if !ok {
				return nil, fmt.Errorf("no type spec for %s", errorName)
			}
			iface, ok := spec.Type.(*ast.InterfaceType)
			if !ok {
				return nil, fmt.Errorf("%s is not an interface", errorName)
			}
			if iface.Methods.NumFields() != 1 {
				return nil, fmt.Errorf("expected 1 method for %s, got %v", errorName, iface.Methods.NumFields())
			}
			method := iface.Methods.List[0]
			if len(method.Names) != 1 {
				return nil, fmt.Errorf("expected 1 name for %v, got %v", method, len(method.Names))
			}
			name := method.Names[0].Name
			result.Declaration.node = method
			rng := NewMappedRange(snapshot.FileSet(), builtin.Mapper, method.Pos(), method.Pos()+token.Pos(len(name)))
			result.Declaration.MappedRange = append(result.Declaration.MappedRange, rng)
			return result, nil
		}
	}

	// If the original position was an embedded field, we want to jump
	// to the field's type definition, not the field's definition.
	if v, ok := result.Declaration.obj.(*types.Var); ok && v.Embedded() {
		// types.Info.Uses contains the embedded field's *types.TypeName.
		if typeName := pkg.GetTypesInfo().Uses[ident]; typeName != nil {
			result.Declaration.obj = typeName
		}
	}

	rng, err := objToMappedRange(snapshot, pkg, result.Declaration.obj)
	if err != nil {
		return nil, err
	}
	result.Declaration.MappedRange = append(result.Declaration.MappedRange, rng)

	declPkg, err := FindPackageFromPos(ctx, snapshot, result.Declaration.obj.Pos())
	if err != nil {
		return nil, err
	}
	if result.Declaration.node, err = snapshot.PosToDecl(ctx, declPkg, result.Declaration.obj.Pos()); err != nil {
		return nil, err
	}
	// Ensure that we have the full declaration, in case the declaration was
	// parsed in ParseExported and therefore could be missing information.
	if result.Declaration.fullDecl, err = fullNode(snapshot, result.Declaration.obj, declPkg); err != nil {
		return nil, err
	}
	typ := pkg.GetTypesInfo().TypeOf(result.ident)
	if typ == nil {
		return result, nil
	}

	result.Inferred = inferredSignature(pkg.GetTypesInfo(), ident)

	result.Type.Object = typeToObject(typ)
	if result.Type.Object != nil {
		// Identifiers with the type "error" are a special case with no position.
		if hasErrorType(result.Type.Object) {
			return result, nil
		}
		if result.Type.MappedRange, err = objToMappedRange(snapshot, pkg, result.Type.Object); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// fullNode tries to extract the full spec corresponding to obj's declaration.
// If the package was not parsed in full, the declaration file will be
// re-parsed to ensure it has complete syntax.
func fullNode(snapshot Snapshot, obj types.Object, pkg Package) (ast.Decl, error) {
	// declaration in a different package... make sure we have full AST information.
	tok := snapshot.FileSet().File(obj.Pos())
	uri := span.URIFromPath(tok.Name())
	pgf, err := pkg.File(uri)
	if err != nil {
		return nil, err
	}
	file := pgf.File
	pos := obj.Pos()
	if pgf.Mode != ParseFull {
		fset := snapshot.FileSet()
		file2, _ := parser.ParseFile(fset, tok.Name(), pgf.Src, parser.AllErrors|parser.ParseComments)
		if file2 != nil {
			offset, err := Offset(tok, obj.Pos())
			if err != nil {
				return nil, err
			}
			file = file2
			tok2 := fset.File(file2.Pos())
			pos = tok2.Pos(offset)
		}
	}
	path, _ := astutil.PathEnclosingInterval(file, pos, pos)
	for _, n := range path {
		if decl, ok := n.(ast.Decl); ok {
			return decl, nil
		}
	}
	return nil, nil
}

// inferredSignature determines the resolved non-generic signature for an
// identifier in an instantiation expression.
//
// If no such signature exists, it returns nil.
func inferredSignature(info *types.Info, id *ast.Ident) *types.Signature {
	inst := typeparams.GetInstances(info)[id]
	sig, _ := inst.Type.(*types.Signature)
	return sig
}

func searchForEnclosing(info *types.Info, path []ast.Node) types.Type {
	for _, n := range path {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if sel, ok := info.Selections[n]; ok {
				recv := Deref(sel.Recv())

				// Keep track of the last exported type seen.
				var exported types.Type
				if named, ok := recv.(*types.Named); ok && named.Obj().Exported() {
					exported = named
				}
				// We don't want the last element, as that's the field or
				// method itself.
				for _, index := range sel.Index()[:len(sel.Index())-1] {
					if r, ok := recv.Underlying().(*types.Struct); ok {
						recv = Deref(r.Field(index).Type())
						if named, ok := recv.(*types.Named); ok && named.Obj().Exported() {
							exported = named
						}
					}
				}
				return exported
			}
		case *ast.CompositeLit:
			if t, ok := info.Types[n]; ok {
				return t.Type
			}
		case *ast.TypeSpec:
			if _, ok := n.Type.(*ast.StructType); ok {
				if t, ok := info.Defs[n.Name]; ok {
					return t.Type()
				}
			}
		}
	}
	return nil
}

func typeToObject(typ types.Type) types.Object {
	switch typ := typ.(type) {
	case *types.Named:
		return typ.Obj()
	case *types.Pointer:
		return typeToObject(typ.Elem())
	case *types.Array:
		return typeToObject(typ.Elem())
	case *types.Slice:
		return typeToObject(typ.Elem())
	case *types.Chan:
		return typeToObject(typ.Elem())
	case *types.Signature:
		// Try to find a return value of a named type. If there's only one
		// such value, jump to its type definition.
		var res types.Object

		results := typ.Results()
		for i := 0; i < results.Len(); i++ {
			obj := typeToObject(results.At(i).Type())
			if obj == nil || hasErrorType(obj) {
				// Skip builtins.
				continue
			}
			if res != nil {
				// The function/method must have only one return value of a named type.
				return nil
			}

			res = obj
		}
		return res
	default:
		return nil
	}
}

func hasErrorType(obj types.Object) bool {
	return types.IsInterface(obj.Type()) && obj.Pkg() == nil && obj.Name() == "error"
}

// importSpec handles positions inside of an *ast.ImportSpec.
func importSpec(snapshot Snapshot, pkg Package, file *ast.File, pos token.Pos) (*IdentifierInfo, error) {
	var imp *ast.ImportSpec
	for _, spec := range file.Imports {
		if spec.Path.Pos() <= pos && pos < spec.Path.End() {
			imp = spec
		}
	}
	if imp == nil {
		return nil, nil
	}
	importPath, err := strconv.Unquote(imp.Path.Value)
	if err != nil {
		return nil, errors.Errorf("import path not quoted: %s (%v)", imp.Path.Value, err)
	}
	result := &IdentifierInfo{
		Snapshot: snapshot,
		Name:     importPath,
		pkg:      pkg,
	}
	if result.MappedRange, err = posToMappedRange(snapshot, pkg, imp.Path.Pos(), imp.Path.End()); err != nil {
		return nil, err
	}
	// Consider the "declaration" of an import spec to be the imported package.
	importedPkg, err := pkg.GetImport(importPath)
	if err != nil {
		return nil, err
	}
	// Return all of the files in the package as the definition of the import spec.
	for _, dst := range importedPkg.GetSyntax() {
		rng, err := posToMappedRange(snapshot, pkg, dst.Pos(), dst.End())
		if err != nil {
			return nil, err
		}
		result.Declaration.MappedRange = append(result.Declaration.MappedRange, rng)
	}

	result.Declaration.node = imp
	return result, nil
}

// typeSwitchImplicits returns all the implicit type switch objects that
// correspond to the leaf *ast.Ident. It also returns the original type
// associated with the identifier (outside of a case clause).
func typeSwitchImplicits(pkg Package, path []ast.Node) ([]types.Object, types.Type) {
	ident, _ := path[0].(*ast.Ident)
	if ident == nil {
		return nil, nil
	}

	var (
		ts     *ast.TypeSwitchStmt
		assign *ast.AssignStmt
		cc     *ast.CaseClause
		obj    = pkg.GetTypesInfo().ObjectOf(ident)
	)

	// Walk our ancestors to determine if our leaf ident refers to a
	// type switch variable, e.g. the "a" from "switch a := b.(type)".
Outer:
	for i := 1; i < len(path); i++ {
		switch n := path[i].(type) {
		case *ast.AssignStmt:
			// Check if ident is the "a" in "a := foo.(type)". The "a" in
			// this case has no types.Object, so check for ident equality.
			if len(n.Lhs) == 1 && n.Lhs[0] == ident {
				assign = n
			}
		case *ast.CaseClause:
			// Check if ident is a use of "a" within a case clause. Each
			// case clause implicitly maps "a" to a different types.Object,
			// so check if ident's object is the case clause's implicit
			// object.
			if obj != nil && pkg.GetTypesInfo().Implicits[n] == obj {
				cc = n
			}
		case *ast.TypeSwitchStmt:
			// Look for the type switch that owns our previously found
			// *ast.AssignStmt or *ast.CaseClause.
			if n.Assign == assign {
				ts = n
				break Outer
			}

			for _, stmt := range n.Body.List {
				if stmt == cc {
					ts = n
					break Outer
				}
			}
		}
	}
	if ts == nil {
		return nil, nil
	}
	// Our leaf ident refers to a type switch variable. Fan out to the
	// type switch's implicit case clause objects.
	var objs []types.Object
	for _, cc := range ts.Body.List {
		if ccObj := pkg.GetTypesInfo().Implicits[cc]; ccObj != nil {
			objs = append(objs, ccObj)
		}
	}
	// The right-hand side of a type switch should only have one
	// element, and we need to track its type in order to generate
	// hover information for implicit type switch variables.
	var typ types.Type
	if assign, ok := ts.Assign.(*ast.AssignStmt); ok && len(assign.Rhs) == 1 {
		if rhs := assign.Rhs[0].(*ast.TypeAssertExpr); ok {
			typ = pkg.GetTypesInfo().TypeOf(rhs.X)
		}
	}
	return objs, typ
}
