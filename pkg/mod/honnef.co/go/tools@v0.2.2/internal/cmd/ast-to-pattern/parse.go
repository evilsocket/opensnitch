package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"text/template"
)

var tmplDecl = template.Must(template.New("").Parse(`` +
	`package p; {{ . }}`))

var tmplExprs = template.Must(template.New("").Parse(`` +
	`package p; var _ = []interface{}{ {{ . }}, }`))

var tmplStmts = template.Must(template.New("").Parse(`` +
	`package p; func _() { {{ . }} }`))

var tmplType = template.Must(template.New("").Parse(`` +
	`package p; var _ {{ . }}`))

var tmplValSpec = template.Must(template.New("").Parse(`` +
	`package p; var {{ . }}`))

func execTmpl(tmpl *template.Template, src string) string {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, src); err != nil {
		panic(err)
	}
	return buf.String()
}

func noBadNodes(node ast.Node) bool {
	any := false
	ast.Inspect(node, func(n ast.Node) bool {
		if any {
			return false
		}
		switch n.(type) {
		case *ast.BadExpr, *ast.BadDecl:
			any = true
		}
		return true
	})
	return !any
}

func parseType(fset *token.FileSet, src string) (ast.Expr, *ast.File, error) {
	asType := execTmpl(tmplType, src)
	f, err := parser.ParseFile(fset, "", asType, 0)
	if err != nil {
		return nil, nil, err
	}
	vs := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.ValueSpec)
	return vs.Type, f, nil
}

// parseDetectingNode tries its best to parse the ast.Node contained in src, as
// one of: *ast.File, ast.Decl, ast.Expr, ast.Stmt, *ast.ValueSpec.
// It also returns the *ast.File used for the parsing, so that the returned node
// can be easily type-checked.
func parseDetectingNode(fset *token.FileSet, src string) (interface{}, error) {
	file := fset.AddFile("", fset.Base(), len(src))
	scan := scanner.Scanner{}
	scan.Init(file, []byte(src), nil, 0)
	if _, tok, _ := scan.Scan(); tok == token.EOF {
		return nil, fmt.Errorf("empty source code")
	}
	var mainErr error

	// first try as a whole file
	if f, err := parser.ParseFile(fset, "", src, 0); err == nil && noBadNodes(f) {
		return f, nil
	}

	// then as a single declaration, or many
	asDecl := execTmpl(tmplDecl, src)
	if f, err := parser.ParseFile(fset, "", asDecl, 0); err == nil && noBadNodes(f) {
		if len(f.Decls) == 1 {
			return f.Decls[0], nil
		}
		return f, nil
	}

	// then as value expressions
	asExprs := execTmpl(tmplExprs, src)
	if f, err := parser.ParseFile(fset, "", asExprs, 0); err == nil && noBadNodes(f) {
		vs := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.ValueSpec)
		cl := vs.Values[0].(*ast.CompositeLit)
		if len(cl.Elts) == 1 {
			return cl.Elts[0], nil
		}
		return cl.Elts, nil
	}

	// then try as statements
	asStmts := execTmpl(tmplStmts, src)
	if f, err := parser.ParseFile(fset, "", asStmts, 0); err == nil && noBadNodes(f) {
		bl := f.Decls[0].(*ast.FuncDecl).Body
		if len(bl.List) == 1 {
			return bl.List[0], nil
		}
		return bl.List, nil
	} else {
		// Statements is what covers most cases, so it will give
		// the best overall error message. Show positions
		// relative to where the user's code is put in the
		// template.
		mainErr = err
	}

	// type expressions not yet picked up, for e.g. chans and interfaces
	if typ, f, err := parseType(fset, src); err == nil && noBadNodes(f) {
		return typ, nil
	}

	// value specs
	asValSpec := execTmpl(tmplValSpec, src)
	if f, err := parser.ParseFile(fset, "", asValSpec, 0); err == nil && noBadNodes(f) {
		vs := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.ValueSpec)
		return vs, nil
	}
	return nil, mainErr
}
