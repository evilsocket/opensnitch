// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package source

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/internal/event"
	"golang.org/x/tools/internal/lsp/protocol"
	errors "golang.org/x/xerrors"
)

func SignatureHelp(ctx context.Context, snapshot Snapshot, fh FileHandle, pos protocol.Position) (*protocol.SignatureInformation, int, error) {
	ctx, done := event.Start(ctx, "source.SignatureHelp")
	defer done()

	pkg, pgf, err := GetParsedFile(ctx, snapshot, fh, NarrowestPackage)
	if err != nil {
		return nil, 0, errors.Errorf("getting file for SignatureHelp: %w", err)
	}
	spn, err := pgf.Mapper.PointSpan(pos)
	if err != nil {
		return nil, 0, err
	}
	rng, err := spn.Range(pgf.Mapper.Converter)
	if err != nil {
		return nil, 0, err
	}
	// Find a call expression surrounding the query position.
	var callExpr *ast.CallExpr
	path, _ := astutil.PathEnclosingInterval(pgf.File, rng.Start, rng.Start)
	if path == nil {
		return nil, 0, errors.Errorf("cannot find node enclosing position")
	}
FindCall:
	for _, node := range path {
		switch node := node.(type) {
		case *ast.CallExpr:
			if rng.Start >= node.Lparen && rng.Start <= node.Rparen {
				callExpr = node
				break FindCall
			}
		case *ast.FuncLit, *ast.FuncType:
			// The user is within an anonymous function,
			// which may be the parameter to the *ast.CallExpr.
			// Don't show signature help in this case.
			return nil, 0, errors.Errorf("no signature help within a function declaration")
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				return nil, 0, errors.Errorf("no signature help within a string literal")
			}
		}

	}
	if callExpr == nil || callExpr.Fun == nil {
		return nil, 0, errors.Errorf("cannot find an enclosing function")
	}

	qf := Qualifier(pgf.File, pkg.GetTypes(), pkg.GetTypesInfo())

	// Get the object representing the function, if available.
	// There is no object in certain cases such as calling a function returned by
	// a function (e.g. "foo()()").
	var obj types.Object
	switch t := callExpr.Fun.(type) {
	case *ast.Ident:
		obj = pkg.GetTypesInfo().ObjectOf(t)
	case *ast.SelectorExpr:
		obj = pkg.GetTypesInfo().ObjectOf(t.Sel)
	}

	// Handle builtin functions separately.
	if obj, ok := obj.(*types.Builtin); ok {
		return builtinSignature(ctx, snapshot, callExpr, obj.Name(), rng.Start)
	}

	// Get the type information for the function being called.
	sigType := pkg.GetTypesInfo().TypeOf(callExpr.Fun)
	if sigType == nil {
		return nil, 0, errors.Errorf("cannot get type for Fun %[1]T (%[1]v)", callExpr.Fun)
	}

	sig, _ := sigType.Underlying().(*types.Signature)
	if sig == nil {
		return nil, 0, errors.Errorf("cannot find signature for Fun %[1]T (%[1]v)", callExpr.Fun)
	}

	activeParam := activeParameter(callExpr, sig.Params().Len(), sig.Variadic(), rng.Start)

	var (
		name    string
		comment *ast.CommentGroup
	)
	if obj != nil {
		declPkg, err := FindPackageFromPos(ctx, snapshot, obj.Pos())
		if err != nil {
			return nil, 0, err
		}
		node, err := snapshot.PosToDecl(ctx, declPkg, obj.Pos())
		if err != nil {
			return nil, 0, err
		}
		rng, err := objToMappedRange(snapshot, pkg, obj)
		if err != nil {
			return nil, 0, err
		}
		decl := Declaration{
			obj:  obj,
			node: node,
		}
		decl.MappedRange = append(decl.MappedRange, rng)
		d, err := HoverInfo(ctx, snapshot, pkg, decl.obj, decl.node, nil)
		if err != nil {
			return nil, 0, err
		}
		name = obj.Name()
		comment = d.comment
	} else {
		name = "func"
	}
	s := NewSignature(ctx, snapshot, pkg, sig, comment, qf)
	paramInfo := make([]protocol.ParameterInformation, 0, len(s.params))
	for _, p := range s.params {
		paramInfo = append(paramInfo, protocol.ParameterInformation{Label: p})
	}
	return &protocol.SignatureInformation{
		Label:         name + s.Format(),
		Documentation: s.doc,
		Parameters:    paramInfo,
	}, activeParam, nil
}

func builtinSignature(ctx context.Context, snapshot Snapshot, callExpr *ast.CallExpr, name string, pos token.Pos) (*protocol.SignatureInformation, int, error) {
	sig, err := NewBuiltinSignature(ctx, snapshot, name)
	if err != nil {
		return nil, 0, err
	}
	paramInfo := make([]protocol.ParameterInformation, 0, len(sig.params))
	for _, p := range sig.params {
		paramInfo = append(paramInfo, protocol.ParameterInformation{Label: p})
	}
	activeParam := activeParameter(callExpr, len(sig.params), sig.variadic, pos)
	return &protocol.SignatureInformation{
		Label:         sig.name + sig.Format(),
		Documentation: sig.doc,
		Parameters:    paramInfo,
	}, activeParam, nil

}

func activeParameter(callExpr *ast.CallExpr, numParams int, variadic bool, pos token.Pos) (activeParam int) {
	if len(callExpr.Args) == 0 {
		return 0
	}
	// First, check if the position is even in the range of the arguments.
	start, end := callExpr.Lparen, callExpr.Rparen
	if !(start <= pos && pos <= end) {
		return 0
	}
	for _, expr := range callExpr.Args {
		if start == token.NoPos {
			start = expr.Pos()
		}
		end = expr.End()
		if start <= pos && pos <= end {
			break
		}
		// Don't advance the active parameter for the last parameter of a variadic function.
		if !variadic || activeParam < numParams-1 {
			activeParam++
		}
		start = expr.Pos() + 1 // to account for commas
	}
	return activeParam
}
