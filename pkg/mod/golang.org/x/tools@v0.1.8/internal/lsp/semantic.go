// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lsp

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/tools/internal/event"
	"golang.org/x/tools/internal/lsp/protocol"
	"golang.org/x/tools/internal/lsp/source"
	"golang.org/x/tools/internal/lsp/template"
	"golang.org/x/tools/internal/typeparams"
	errors "golang.org/x/xerrors"
)

// The LSP says that errors for the semantic token requests should only be returned
// for exceptions (a word not otherwise defined). This code treats a too-large file
// as an exception. On parse errors, the code does what it can.

// reject full semantic token requests for large files
const maxFullFileSize int = 100000

// to control comprehensive logging of decisions (gopls semtok foo.go > /dev/null shows log output)
// semDebug should NEVER be true in checked-in code
const semDebug = false

func (s *Server) semanticTokensFull(ctx context.Context, p *protocol.SemanticTokensParams) (*protocol.SemanticTokens, error) {
	ret, err := s.computeSemanticTokens(ctx, p.TextDocument, nil)
	return ret, err
}

func (s *Server) semanticTokensFullDelta(ctx context.Context, p *protocol.SemanticTokensDeltaParams) (interface{}, error) {
	return nil, errors.Errorf("implement SemanticTokensFullDelta")
}

func (s *Server) semanticTokensRange(ctx context.Context, p *protocol.SemanticTokensRangeParams) (*protocol.SemanticTokens, error) {
	ret, err := s.computeSemanticTokens(ctx, p.TextDocument, &p.Range)
	return ret, err
}

func (s *Server) semanticTokensRefresh(ctx context.Context) error {
	// in the code, but not in the protocol spec
	return errors.Errorf("implement SemanticTokensRefresh")
}

func (s *Server) computeSemanticTokens(ctx context.Context, td protocol.TextDocumentIdentifier, rng *protocol.Range) (*protocol.SemanticTokens, error) {
	ans := protocol.SemanticTokens{
		Data: []uint32{},
	}
	snapshot, fh, ok, release, err := s.beginFileRequest(ctx, td.URI, source.UnknownKind)
	defer release()
	if !ok {
		return nil, err
	}
	vv := snapshot.View()
	if !vv.Options().SemanticTokens {
		// return an error, so if the option changes
		// the client won't remember the wrong answer
		return nil, errors.Errorf("semantictokens are disabled")
	}
	if fh.Kind() == source.Tmpl {
		// this is a little cumbersome to avoid both exporting 'encoded' and its methods
		// and to avoid import cycles
		e := &encoded{
			ctx:      ctx,
			rng:      rng,
			tokTypes: s.session.Options().SemanticTypes,
			tokMods:  s.session.Options().SemanticMods,
		}
		add := func(line, start uint32, len uint32) {
			e.add(line, start, len, tokMacro, nil)
		}
		data := func() []uint32 {
			return e.Data()
		}
		return template.SemanticTokens(ctx, snapshot, fh.URI(), add, data)
	}
	if fh.Kind() != source.Go {
		return nil, nil
	}
	pkg, err := snapshot.PackageForFile(ctx, fh.URI(), source.TypecheckFull, source.WidestPackage)
	if err != nil {
		return nil, err
	}
	pgf, err := pkg.File(fh.URI())
	if err != nil {
		return nil, err
	}
	// ignore pgf.ParseErr. Do what we can.
	if rng == nil && len(pgf.Src) > maxFullFileSize {
		err := fmt.Errorf("semantic tokens: file %s too large for full (%d>%d)",
			fh.URI().Filename(), len(pgf.Src), maxFullFileSize)
		return nil, err
	}
	e := &encoded{
		ctx:      ctx,
		pgf:      pgf,
		rng:      rng,
		ti:       pkg.GetTypesInfo(),
		pkg:      pkg,
		fset:     snapshot.FileSet(),
		tokTypes: s.session.Options().SemanticTypes,
		tokMods:  s.session.Options().SemanticMods,
	}
	if err := e.init(); err != nil {
		// e.init should never return an error, unless there's some
		// seemingly impossible race condition
		return nil, err
	}
	e.semantics()
	ans.Data = e.Data()
	// For delta requests, but we've never seen any.
	ans.ResultID = fmt.Sprintf("%v", time.Now())
	return &ans, nil
}

func (e *encoded) semantics() {
	f := e.pgf.File
	// may not be in range, but harmless
	e.token(f.Package, len("package"), tokKeyword, nil)
	e.token(f.Name.NamePos, len(f.Name.Name), tokNamespace, nil)
	inspect := func(n ast.Node) bool {
		return e.inspector(n)
	}
	for _, d := range f.Decls {
		// only look at the decls that overlap the range
		start, end := d.Pos(), d.End()
		if end <= e.start || start >= e.end {
			continue
		}
		ast.Inspect(d, inspect)
	}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if !strings.Contains(c.Text, "\n") {
				e.token(c.Pos(), len(c.Text), tokComment, nil)
				continue
			}
			e.multiline(c.Pos(), c.End(), c.Text, tokComment)
		}
	}
}

type tokenType string

const (
	tokNamespace tokenType = "namespace"
	tokType      tokenType = "type"
	tokInterface tokenType = "interface"
	tokTypeParam tokenType = "typeParameter"
	tokParameter tokenType = "parameter"
	tokVariable  tokenType = "variable"
	tokMethod    tokenType = "method"
	tokFunction  tokenType = "function"
	tokKeyword   tokenType = "keyword"
	tokComment   tokenType = "comment"
	tokString    tokenType = "string"
	tokNumber    tokenType = "number"
	tokOperator  tokenType = "operator"

	tokMacro tokenType = "macro" // for templates
)

func (e *encoded) token(start token.Pos, leng int, typ tokenType, mods []string) {

	if !start.IsValid() {
		// This is not worth reporting
		return
	}
	if start >= e.end || start+token.Pos(leng) <= e.start {
		return
	}
	// want a line and column from start (in LSP coordinates)
	// [//line directives should be ignored]
	rng := source.NewMappedRange(e.fset, e.pgf.Mapper, start, start+token.Pos(leng))
	lspRange, err := rng.Range()
	if err != nil {
		// possibly a //line directive. TODO(pjw): fix this somehow
		// "column mapper is for file...instead of..."
		// "line is beyond end of file..."
		// see line 116 of internal/span/token.go which uses Position not PositionFor
		// (it is too verbose to print the error on every token. some other RPC will fail)
		// event.Error(e.ctx, "failed to convert to range", err)
		return
	}
	if lspRange.End.Line != lspRange.Start.Line {
		// this happens if users are typing at the end of the file, but report nothing
		return
	}
	// token is all on one line
	length := lspRange.End.Character - lspRange.Start.Character
	e.add(lspRange.Start.Line, lspRange.Start.Character, length, typ, mods)
}

func (e *encoded) add(line, start uint32, len uint32, tok tokenType, mod []string) {
	x := semItem{line, start, len, tok, mod}
	e.items = append(e.items, x)
}

// semItem represents a token found walking the parse tree
type semItem struct {
	line, start uint32
	len         uint32
	typeStr     tokenType
	mods        []string
}

type encoded struct {
	// the generated data
	items []semItem

	ctx               context.Context
	tokTypes, tokMods []string
	pgf               *source.ParsedGoFile
	rng               *protocol.Range
	ti                *types.Info
	types             *types.Package
	pkg               source.Package
	fset              *token.FileSet
	// allowed starting and ending token.Pos, set by init
	// used to avoid looking at declarations not in range
	start, end token.Pos
	// path from the root of the parse tree, used for debugging
	stack []ast.Node
}

// convert the stack to a string, for debugging
func (e *encoded) strStack() string {
	msg := []string{"["}
	for i := len(e.stack) - 1; i >= 0; i-- {
		s := e.stack[i]
		msg = append(msg, fmt.Sprintf("%T", s)[5:])
	}
	if len(e.stack) > 0 {
		loc := e.stack[len(e.stack)-1].Pos()
		if !source.InRange(e.pgf.Tok, loc) {
			msg = append(msg, fmt.Sprintf("invalid position %v for %s", loc, e.pgf.URI))
		} else if locInRange(e.pgf.Tok, loc) {
			add := e.pgf.Tok.PositionFor(loc, false)
			nm := filepath.Base(add.Filename)
			msg = append(msg, fmt.Sprintf("(%s:%d,col:%d)", nm, add.Line, add.Column))
		} else {
			msg = append(msg, fmt.Sprintf("(loc %d out of range)", loc))
		}
	}
	msg = append(msg, "]")
	return strings.Join(msg, " ")
}

// avoid panic in token.PostionFor() when typing at the end of the file
func locInRange(f *token.File, loc token.Pos) bool {
	return f.Base() <= int(loc) && int(loc) < f.Base()+f.Size()
}

// find the line in the source
func (e *encoded) srcLine(x ast.Node) string {
	file := e.pgf.Tok
	line := file.Line(x.Pos())
	start, err := source.Offset(file, file.LineStart(line))
	if err != nil {
		return ""
	}
	end := start
	for ; end < len(e.pgf.Src) && e.pgf.Src[end] != '\n'; end++ {

	}
	ans := e.pgf.Src[start:end]
	return string(ans)
}

func (e *encoded) inspector(n ast.Node) bool {
	pop := func() {
		e.stack = e.stack[:len(e.stack)-1]
	}
	if n == nil {
		pop()
		return true
	}
	e.stack = append(e.stack, n)
	switch x := n.(type) {
	case *ast.ArrayType:
	case *ast.AssignStmt:
		e.token(x.TokPos, len(x.Tok.String()), tokOperator, nil)
	case *ast.BasicLit:
		if strings.Contains(x.Value, "\n") {
			// has to be a string
			e.multiline(x.Pos(), x.End(), x.Value, tokString)
			break
		}
		ln := len(x.Value)
		what := tokNumber
		if x.Kind == token.STRING {
			what = tokString
			if _, ok := e.stack[len(e.stack)-2].(*ast.Field); ok {
				// struct tags (this is probably pointless, as the
				// TextMate grammar will treat all the other comments the same)
				what = tokComment
			}
		}
		e.token(x.Pos(), ln, what, nil)
	case *ast.BinaryExpr:
		e.token(x.OpPos, len(x.Op.String()), tokOperator, nil)
	case *ast.BlockStmt:
	case *ast.BranchStmt:
		e.token(x.TokPos, len(x.Tok.String()), tokKeyword, nil)
		// There's no semantic encoding for labels
	case *ast.CallExpr:
		if x.Ellipsis != token.NoPos {
			e.token(x.Ellipsis, len("..."), tokOperator, nil)
		}
	case *ast.CaseClause:
		iam := "case"
		if x.List == nil {
			iam = "default"
		}
		e.token(x.Case, len(iam), tokKeyword, nil)
	case *ast.ChanType:
		// chan | chan <- | <- chan
		if x.Arrow == token.NoPos || x.Arrow != x.Begin {
			e.token(x.Begin, len("chan"), tokKeyword, nil)
			break
		}
		pos := e.findKeyword("chan", x.Begin+2, x.Value.Pos())
		e.token(pos, len("chan"), tokKeyword, nil)
	case *ast.CommClause:
		iam := len("case")
		if x.Comm == nil {
			iam = len("default")
		}
		e.token(x.Case, iam, tokKeyword, nil)
	case *ast.CompositeLit:
	case *ast.DeclStmt:
	case *ast.DeferStmt:
		e.token(x.Defer, len("defer"), tokKeyword, nil)
	case *ast.Ellipsis:
		e.token(x.Ellipsis, len("..."), tokOperator, nil)
	case *ast.EmptyStmt:
	case *ast.ExprStmt:
	case *ast.Field:
	case *ast.FieldList:
	case *ast.ForStmt:
		e.token(x.For, len("for"), tokKeyword, nil)
	case *ast.FuncDecl:
	case *ast.FuncLit:
	case *ast.FuncType:
		if x.Func != token.NoPos {
			e.token(x.Func, len("func"), tokKeyword, nil)
		}
	case *ast.GenDecl:
		e.token(x.TokPos, len(x.Tok.String()), tokKeyword, nil)
	case *ast.GoStmt:
		e.token(x.Go, len("go"), tokKeyword, nil)
	case *ast.Ident:
		e.ident(x)
	case *ast.IfStmt:
		e.token(x.If, len("if"), tokKeyword, nil)
		if x.Else != nil {
			// x.Body.End() or x.Body.End()+1, not that it matters
			pos := e.findKeyword("else", x.Body.End(), x.Else.Pos())
			e.token(pos, len("else"), tokKeyword, nil)
		}
	case *ast.ImportSpec:
		e.importSpec(x)
		pop()
		return false
	case *ast.IncDecStmt:
		e.token(x.TokPos, len(x.Tok.String()), tokOperator, nil)
	case *ast.IndexExpr:
	case *typeparams.IndexListExpr: // accomodate generics
	case *ast.InterfaceType:
		e.token(x.Interface, len("interface"), tokKeyword, nil)
	case *ast.KeyValueExpr:
	case *ast.LabeledStmt:
	case *ast.MapType:
		e.token(x.Map, len("map"), tokKeyword, nil)
	case *ast.ParenExpr:
	case *ast.RangeStmt:
		e.token(x.For, len("for"), tokKeyword, nil)
		// x.TokPos == token.NoPos is legal (for range foo {})
		offset := x.TokPos
		if offset == token.NoPos {
			offset = x.For
		}
		pos := e.findKeyword("range", offset, x.X.Pos())
		e.token(pos, len("range"), tokKeyword, nil)
	case *ast.ReturnStmt:
		e.token(x.Return, len("return"), tokKeyword, nil)
	case *ast.SelectStmt:
		e.token(x.Select, len("select"), tokKeyword, nil)
	case *ast.SelectorExpr:
	case *ast.SendStmt:
		e.token(x.Arrow, len("<-"), tokOperator, nil)
	case *ast.SliceExpr:
	case *ast.StarExpr:
		e.token(x.Star, len("*"), tokOperator, nil)
	case *ast.StructType:
		e.token(x.Struct, len("struct"), tokKeyword, nil)
	case *ast.SwitchStmt:
		e.token(x.Switch, len("switch"), tokKeyword, nil)
	case *ast.TypeAssertExpr:
		if x.Type == nil {
			pos := e.findKeyword("type", x.Lparen, x.Rparen)
			e.token(pos, len("type"), tokKeyword, nil)
		}
	case *ast.TypeSpec:
	case *ast.TypeSwitchStmt:
		e.token(x.Switch, len("switch"), tokKeyword, nil)
	case *ast.UnaryExpr:
		e.token(x.OpPos, len(x.Op.String()), tokOperator, nil)
	case *ast.ValueSpec:
	// things only seen with parsing or type errors, so ignore them
	case *ast.BadDecl, *ast.BadExpr, *ast.BadStmt:
		return true
	// not going to see these
	case *ast.File, *ast.Package:
		e.unexpected(fmt.Sprintf("implement %T %s", x, e.pgf.Tok.PositionFor(x.Pos(), false)))
	// other things we knowingly ignore
	case *ast.Comment, *ast.CommentGroup:
		pop()
		return false
	default:
		e.unexpected(fmt.Sprintf("failed to implement %T", x))
	}
	return true
}

func (e *encoded) ident(x *ast.Ident) {
	if e.ti == nil {
		what, mods := e.unkIdent(x)
		if what != "" {
			e.token(x.Pos(), len(x.String()), what, mods)
		}
		if semDebug {
			log.Printf(" nil %s/nil/nil %q %v %s", x.String(), what, mods, e.strStack())
		}
		return
	}
	def := e.ti.Defs[x]
	if def != nil {
		what, mods := e.definitionFor(x, def)
		if what != "" {
			e.token(x.Pos(), len(x.String()), what, mods)
		}
		if semDebug {
			log.Printf(" for %s/%T/%T got %s %v (%s)", x.String(), def, def.Type(), what, mods, e.strStack())
		}
		return
	}
	use := e.ti.Uses[x]
	tok := func(pos token.Pos, lng int, tok tokenType, mods []string) {
		e.token(pos, lng, tok, mods)
		q := "nil"
		if use != nil {
			q = fmt.Sprintf("%T", use.Type())
		}
		if semDebug {
			log.Printf(" use %s/%T/%s got %s %v (%s)", x.String(), use, q, tok, mods, e.strStack())
		}
	}

	switch y := use.(type) {
	case nil:
		what, mods := e.unkIdent(x)
		if what != "" {
			tok(x.Pos(), len(x.String()), what, mods)
		} else if semDebug {
			// tok() wasn't called, so didn't log
			log.Printf(" nil %s/%T/nil %q %v (%s)", x.String(), use, what, mods, e.strStack())
		}
		return
	case *types.Builtin:
		tok(x.NamePos, len(x.Name), tokFunction, []string{"defaultLibrary"})
	case *types.Const:
		mods := []string{"readonly"}
		tt := y.Type()
		if _, ok := tt.(*types.Basic); ok {
			tok(x.Pos(), len(x.String()), tokVariable, mods)
			break
		}
		if ttx, ok := tt.(*types.Named); ok {
			if x.String() == "iota" {
				e.unexpected(fmt.Sprintf("iota:%T", ttx))
			}
			if _, ok := ttx.Underlying().(*types.Basic); ok {
				tok(x.Pos(), len(x.String()), tokVariable, mods)
				break
			}
			e.unexpected(fmt.Sprintf("%q/%T", x.String(), tt))
		}
		// can this happen? Don't think so
		e.unexpected(fmt.Sprintf("%s %T %#v", x.String(), tt, tt))
	case *types.Func:
		tok(x.Pos(), len(x.Name), tokFunction, nil)
	case *types.Label:
		// nothing to map it to
	case *types.Nil:
		// nil is a predeclared identifier
		tok(x.Pos(), len("nil"), tokVariable, []string{"readonly", "defaultLibrary"})
	case *types.PkgName:
		tok(x.Pos(), len(x.Name), tokNamespace, nil)
	case *types.TypeName: // could be a tokTpeParam
		var mods []string
		if _, ok := y.Type().(*types.Basic); ok {
			mods = []string{"defaultLibrary"}
		} else if _, ok := y.Type().(*typeparams.TypeParam); ok {
			tok(x.Pos(), len(x.String()), tokTypeParam, mods)
			break
		}
		tok(x.Pos(), len(x.String()), tokType, mods)
	case *types.Var:
		if isSignature(y) {
			tok(x.Pos(), len(x.Name), tokFunction, nil)
		} else if _, ok := y.Type().(*typeparams.TypeParam); ok {
			tok(x.Pos(), len(x.Name), tokTypeParam, nil)
		} else {
			tok(x.Pos(), len(x.Name), tokVariable, nil)
		}
	default:
		// can't happen
		if use == nil {
			msg := fmt.Sprintf("%#v/%#v %#v %#v", x, x.Obj, e.ti.Defs[x], e.ti.Uses[x])
			e.unexpected(msg)
		}
		if use.Type() != nil {
			e.unexpected(fmt.Sprintf("%s %T/%T,%#v", x.String(), use, use.Type(), use))
		} else {
			e.unexpected(fmt.Sprintf("%s %T", x.String(), use))
		}
	}
}

func isSignature(use types.Object) bool {
	if true {
		return false //PJW: fix after generics seem ok
	}
	if _, ok := use.(*types.Var); !ok {
		return false
	}
	v := use.Type()
	if v == nil {
		return false
	}
	if _, ok := v.(*types.Signature); ok {
		return true
	}
	return false
}

// both e.ti.Defs and e.ti.Uses are nil. use the parse stack.
// a lot of these only happen when the package doesn't compile
// but in that case it is all best-effort from the parse tree
func (e *encoded) unkIdent(x *ast.Ident) (tokenType, []string) {
	def := []string{"definition"}
	n := len(e.stack) - 2 // parent of Ident
	if n < 0 {
		e.unexpected("no stack?")
		return "", nil
	}
	switch nd := e.stack[n].(type) {
	case *ast.BinaryExpr, *ast.UnaryExpr, *ast.ParenExpr, *ast.StarExpr,
		*ast.IncDecStmt, *ast.SliceExpr, *ast.ExprStmt, *ast.IndexExpr,
		*ast.ReturnStmt, *ast.ChanType, *ast.SendStmt,
		*ast.ForStmt,      // possibly incomplete
		*ast.IfStmt,       /* condition */
		*ast.KeyValueExpr: // either key or value
		return tokVariable, nil
	case *typeparams.IndexListExpr: // generic?
		return tokVariable, nil
	case *ast.Ellipsis:
		return tokType, nil
	case *ast.CaseClause:
		if n-2 >= 0 {
			if _, ok := e.stack[n-2].(*ast.TypeSwitchStmt); ok {
				return tokType, nil
			}
		}
		return tokVariable, nil
	case *ast.ArrayType:
		if x == nd.Len {
			// or maybe a Type Param, but we can't just from the parse tree
			return tokVariable, nil
		} else {
			return tokType, nil
		}
	case *ast.MapType:
		return tokType, nil
	case *ast.CallExpr:
		if x == nd.Fun {
			return tokFunction, nil
		}
		return tokVariable, nil
	case *ast.SwitchStmt:
		return tokVariable, nil
	case *ast.TypeAssertExpr:
		if x == nd.X {
			return tokVariable, nil
		} else if x == nd.Type {
			return tokType, nil
		}
	case *ast.ValueSpec:
		for _, p := range nd.Names {
			if p == x {
				return tokVariable, def
			}
		}
		for _, p := range nd.Values {
			if p == x {
				return tokVariable, nil
			}
		}
		return tokType, nil
	case *ast.SelectorExpr: // e.ti.Selections[nd] is nil, so no help
		if n-1 >= 0 {
			if ce, ok := e.stack[n-1].(*ast.CallExpr); ok {
				// ... CallExpr SelectorExpr Ident (_.x())
				if ce.Fun == nd && nd.Sel == x {
					return tokFunction, nil
				}
			}
		}
		return tokVariable, nil
	case *ast.AssignStmt:
		for _, p := range nd.Lhs {
			// x := ..., or x = ...
			if p == x {
				if nd.Tok != token.DEFINE {
					def = nil
				}
				return tokVariable, def
			}
		}
		// RHS, = x
		return tokVariable, nil
	case *ast.TypeSpec: // it's a type if it is either the Name or the Type
		if x == nd.Type {
			def = nil
		}
		return tokType, def
	case *ast.Field:
		// ident could be type in a field, or a method in an interface type, or a variable
		if x == nd.Type {
			return tokType, nil
		}
		if n-2 >= 0 {
			_, okit := e.stack[n-2].(*ast.InterfaceType)
			_, okfl := e.stack[n-1].(*ast.FieldList)
			if okit && okfl {
				return tokMethod, def
			}
		}
		return tokVariable, nil
	case *ast.LabeledStmt, *ast.BranchStmt:
		// nothing to report
	case *ast.CompositeLit:
		if nd.Type == x {
			return tokType, nil
		}
		return tokVariable, nil
	case *ast.RangeStmt:
		if nd.Tok != token.DEFINE {
			def = nil
		}
		return tokVariable, def
	case *ast.FuncDecl:
		return tokFunction, def
	default:
		msg := fmt.Sprintf("%T undexpected: %s %s%q", nd, x.Name, e.strStack(), e.srcLine(x))
		e.unexpected(msg)
	}
	return "", nil
}

func isDeprecated(n *ast.CommentGroup) bool {
	if n == nil {
		return false
	}
	for _, c := range n.List {
		if strings.HasPrefix(c.Text, "// Deprecated") {
			return true
		}
	}
	return false
}

func (e *encoded) definitionFor(x *ast.Ident, def types.Object) (tokenType, []string) {
	// PJW: def == types.Label? probably a nothing
	// PJW: look into replaceing these syntactic tests with types more generally
	mods := []string{"definition"}
	for i := len(e.stack) - 1; i >= 0; i-- {
		s := e.stack[i]
		switch y := s.(type) {
		case *ast.AssignStmt, *ast.RangeStmt:
			if x.Name == "_" {
				return "", nil // not really a variable
			}
			return tokVariable, mods
		case *ast.GenDecl:
			if isDeprecated(y.Doc) {
				mods = append(mods, "deprecated")
			}
			if y.Tok == token.CONST {
				mods = append(mods, "readonly")
			}
			return tokVariable, mods
		case *ast.FuncDecl:
			// If x is immediately under a FuncDecl, it is a function or method
			if i == len(e.stack)-2 {
				if isDeprecated(y.Doc) {
					mods = append(mods, "deprecated")
				}
				if y.Recv != nil {
					return tokMethod, mods
				}
				return tokFunction, mods
			}
			// if x < ... < FieldList < FuncDecl, this is the receiver, a variable
			if _, ok := e.stack[i+1].(*ast.FieldList); ok {
				return tokVariable, nil
			}
			// if x < ... < FieldList < FuncType < FuncDecl, this is a param
			return tokParameter, mods
		case *ast.FuncType:
			return tokParameter, mods
		case *ast.InterfaceType:
			return tokMethod, mods
		case *ast.TypeSpec:
			// GenDecl/Typespec/FuncType/FieldList/Field/Ident
			// (type A func(b uint64)) (err error)
			// b and err should not be tokType, but tokVaraible
			// and in GenDecl/TpeSpec/StructType/FieldList/Field/Ident
			// (type A struct{b uint64}
			// but on type B struct{C}), C is a type, but is not being defined.
			// GenDecl/TypeSpec/FieldList/Field/Ident is a typeParam
			if _, ok := e.stack[i+1].(*ast.FieldList); ok {
				return tokTypeParam, mods
			}
			fldm := e.stack[len(e.stack)-2]
			if fld, ok := fldm.(*ast.Field); ok {
				// if len(fld.names) == 0 this is a tokType, being used
				if len(fld.Names) == 0 {
					return tokType, nil
				}
				return tokVariable, mods
			}
			return tokType, mods
		}
	}
	// can't happen
	msg := fmt.Sprintf("failed to find the decl for %s", e.pgf.Tok.PositionFor(x.Pos(), false))
	e.unexpected(msg)
	return "", []string{""}
}

func (e *encoded) multiline(start, end token.Pos, val string, tok tokenType) {
	f := e.fset.File(start)
	// the hard part is finding the lengths of lines. include the \n
	leng := func(line int) int {
		n := f.LineStart(line)
		if line >= f.LineCount() {
			return f.Size() - int(n)
		}
		return int(f.LineStart(line+1) - n)
	}
	spos := e.fset.PositionFor(start, false)
	epos := e.fset.PositionFor(end, false)
	sline := spos.Line
	eline := epos.Line
	// first line is from spos.Column to end
	e.token(start, leng(sline)-spos.Column, tok, nil) // leng(sline)-1 - (spos.Column-1)
	for i := sline + 1; i < eline; i++ {
		// intermediate lines are from 1 to end
		e.token(f.LineStart(i), leng(i)-1, tok, nil) // avoid the newline
	}
	// last line is from 1 to epos.Column
	e.token(f.LineStart(eline), epos.Column-1, tok, nil) // columns are 1-based
}

// findKeyword finds a keyword rather than guessing its location
func (e *encoded) findKeyword(keyword string, start, end token.Pos) token.Pos {
	offset := int(start) - e.pgf.Tok.Base()
	last := int(end) - e.pgf.Tok.Base()
	buf := e.pgf.Src
	idx := bytes.Index(buf[offset:last], []byte(keyword))
	if idx != -1 {
		return start + token.Pos(idx)
	}
	//(in unparsable programs: type _ <-<-chan int)
	e.unexpected(fmt.Sprintf("not found:%s %v", keyword, e.fset.PositionFor(start, false)))
	return token.NoPos
}

func (e *encoded) init() error {
	e.start = token.Pos(e.pgf.Tok.Base())
	e.end = e.start + token.Pos(e.pgf.Tok.Size())
	if e.rng == nil {
		return nil
	}
	span, err := e.pgf.Mapper.RangeSpan(*e.rng)
	if err != nil {
		return errors.Errorf("range span (%w) error for %s", err, e.pgf.File.Name)
	}
	e.end = e.start + token.Pos(span.End().Offset())
	e.start += token.Pos(span.Start().Offset())
	return nil
}

func (e *encoded) Data() []uint32 {
	// binary operators, at least, will be out of order
	sort.Slice(e.items, func(i, j int) bool {
		if e.items[i].line != e.items[j].line {
			return e.items[i].line < e.items[j].line
		}
		return e.items[i].start < e.items[j].start
	})
	typeMap, modMap := e.maps()
	// each semantic token needs five values
	// (see Integer Encoding for Tokens in the LSP spec)
	x := make([]uint32, 5*len(e.items))
	var j int
	for i := 0; i < len(e.items); i++ {
		typ, ok := typeMap[e.items[i].typeStr]
		if !ok {
			continue // client doesn't want typeStr
		}
		if i == 0 {
			x[0] = e.items[0].line
		} else {
			x[j] = e.items[i].line - e.items[i-1].line
		}
		x[j+1] = e.items[i].start
		if i > 0 && e.items[i].line == e.items[i-1].line {
			x[j+1] = e.items[i].start - e.items[i-1].start
		}
		x[j+2] = e.items[i].len
		x[j+3] = uint32(typ)
		mask := 0
		for _, s := range e.items[i].mods {
			// modMap[s] is 0 if the client doesn't want this modifier
			mask |= modMap[s]
		}
		x[j+4] = uint32(mask)
		j += 5
	}
	return x[:j]
}

func (e *encoded) importSpec(d *ast.ImportSpec) {
	// a local package name or the last component of the Path
	if d.Name != nil {
		nm := d.Name.String()
		if nm != "_" && nm != "." {
			e.token(d.Name.Pos(), len(nm), tokNamespace, nil)
		}
		return // don't mark anything for . or _
	}
	val := d.Path.Value
	if len(val) < 2 || val[0] != '"' || val[len(val)-1] != '"' {
		// avoid panics on imports without a properly quoted string
		return
	}
	nm := val[1 : len(val)-1] // remove surrounding "s
	// Import strings are implementation defined. Try to match with parse information.
	x, err := e.pkg.GetImport(nm)
	if err != nil {
		// unexpected, but impact is that maybe some import is not colored
		return
	}
	// expect that nm is x.PkgPath and that x.Name() is a component of it
	if x.PkgPath() != nm {
		// don't know how or what to color (if this can happen at all)
		return
	}
	// this is not a precise test: imagine "github.com/nasty/v/v2"
	j := strings.LastIndex(nm, x.Name())
	if j == -1 {
		// name doesn't show up, for whatever reason, so nothing to report
		return
	}
	start := d.Path.Pos() + 1 + token.Pos(j) // skip the initial quote
	e.token(start, len(x.Name()), tokNamespace, nil)
}

// log unexpected state
func (e *encoded) unexpected(msg string) {
	if semDebug {
		panic(msg)
	}
	event.Error(e.ctx, e.strStack(), errors.New(msg))
}

// SemType returns a string equivalent of the type, for gopls semtok
func SemType(n int) string {
	tokTypes := SemanticTypes()
	tokMods := SemanticModifiers()
	if n >= 0 && n < len(tokTypes) {
		return tokTypes[n]
	}
	return fmt.Sprintf("?%d[%d,%d]?", n, len(tokTypes), len(tokMods))
}

// SemMods returns the []string equivalent of the mods, for gopls semtok.
func SemMods(n int) []string {
	tokMods := SemanticModifiers()
	mods := []string{}
	for i := 0; i < len(tokMods); i++ {
		if (n & (1 << uint(i))) != 0 {
			mods = append(mods, tokMods[i])
		}
	}
	return mods
}

func (e *encoded) maps() (map[tokenType]int, map[string]int) {
	tmap := make(map[tokenType]int)
	mmap := make(map[string]int)
	for i, t := range e.tokTypes {
		tmap[tokenType(t)] = i
	}
	for i, m := range e.tokMods {
		mmap[m] = 1 << uint(i) // go 1.12 compatibility
	}
	return tmap, mmap
}

// SemanticTypes to use in case there is no client, as in the command line, or tests
func SemanticTypes() []string {
	return semanticTypes[:]
}

// SemanticModifiers to use in case there is no client.
func SemanticModifiers() []string {
	return semanticModifiers[:]
}

var (
	semanticTypes = [...]string{
		"namespace", "type", "class", "enum", "interface",
		"struct", "typeParameter", "parameter", "variable", "property", "enumMember",
		"event", "function", "method", "macro", "keyword", "modifier", "comment",
		"string", "number", "regexp", "operator",
	}
	semanticModifiers = [...]string{
		"declaration", "definition", "readonly", "static",
		"deprecated", "abstract", "async", "modification", "documentation", "defaultLibrary",
	}
)
