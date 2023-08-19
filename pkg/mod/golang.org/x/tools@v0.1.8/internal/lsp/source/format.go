// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package source provides core features for use by Go editors and tools.
package source

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"strings"
	"text/scanner"

	"golang.org/x/tools/internal/event"
	"golang.org/x/tools/internal/imports"
	"golang.org/x/tools/internal/lsp/diff"
	"golang.org/x/tools/internal/lsp/lsppos"
	"golang.org/x/tools/internal/lsp/protocol"
	"golang.org/x/tools/internal/span"
)

// Format formats a file with a given range.
func Format(ctx context.Context, snapshot Snapshot, fh FileHandle) ([]protocol.TextEdit, error) {
	ctx, done := event.Start(ctx, "source.Format")
	defer done()

	pgf, err := snapshot.ParseGo(ctx, fh, ParseFull)
	if err != nil {
		return nil, err
	}
	// Even if this file has parse errors, it might still be possible to format it.
	// Using format.Node on an AST with errors may result in code being modified.
	// Attempt to format the source of this file instead.
	if pgf.ParseErr != nil {
		formatted, err := formatSource(ctx, fh)
		if err != nil {
			return nil, err
		}
		return computeTextEdits(ctx, snapshot, pgf, string(formatted))
	}

	fset := snapshot.FileSet()

	// format.Node changes slightly from one release to another, so the version
	// of Go used to build the LSP server will determine how it formats code.
	// This should be acceptable for all users, who likely be prompted to rebuild
	// the LSP server on each Go release.
	buf := &bytes.Buffer{}
	if err := format.Node(buf, fset, pgf.File); err != nil {
		return nil, err
	}
	formatted := buf.String()

	// Apply additional formatting, if any is supported. Currently, the only
	// supported additional formatter is gofumpt.
	if format := snapshot.View().Options().Hooks.GofumptFormat; snapshot.View().Options().Gofumpt && format != nil {
		b, err := format(ctx, buf.Bytes())
		if err != nil {
			return nil, err
		}
		formatted = string(b)
	}
	return computeTextEdits(ctx, snapshot, pgf, formatted)
}

func formatSource(ctx context.Context, fh FileHandle) ([]byte, error) {
	_, done := event.Start(ctx, "source.formatSource")
	defer done()

	data, err := fh.Read()
	if err != nil {
		return nil, err
	}
	return format.Source(data)
}

type ImportFix struct {
	Fix   *imports.ImportFix
	Edits []protocol.TextEdit
}

// AllImportsFixes formats f for each possible fix to the imports.
// In addition to returning the result of applying all edits,
// it returns a list of fixes that could be applied to the file, with the
// corresponding TextEdits that would be needed to apply that fix.
func AllImportsFixes(ctx context.Context, snapshot Snapshot, fh FileHandle) (allFixEdits []protocol.TextEdit, editsPerFix []*ImportFix, err error) {
	ctx, done := event.Start(ctx, "source.AllImportsFixes")
	defer done()

	pgf, err := snapshot.ParseGo(ctx, fh, ParseFull)
	if err != nil {
		return nil, nil, err
	}
	if err := snapshot.RunProcessEnvFunc(ctx, func(opts *imports.Options) error {
		allFixEdits, editsPerFix, err = computeImportEdits(snapshot, pgf, opts)
		return err
	}); err != nil {
		return nil, nil, fmt.Errorf("AllImportsFixes: %v", err)
	}
	return allFixEdits, editsPerFix, nil
}

// computeImportEdits computes a set of edits that perform one or all of the
// necessary import fixes.
func computeImportEdits(snapshot Snapshot, pgf *ParsedGoFile, options *imports.Options) (allFixEdits []protocol.TextEdit, editsPerFix []*ImportFix, err error) {
	filename := pgf.URI.Filename()

	// Build up basic information about the original file.
	allFixes, err := imports.FixImports(filename, pgf.Src, options)
	if err != nil {
		return nil, nil, err
	}

	allFixEdits, err = computeFixEdits(snapshot, pgf, options, allFixes)
	if err != nil {
		return nil, nil, err
	}

	// Apply all of the import fixes to the file.
	// Add the edits for each fix to the result.
	for _, fix := range allFixes {
		edits, err := computeFixEdits(snapshot, pgf, options, []*imports.ImportFix{fix})
		if err != nil {
			return nil, nil, err
		}
		editsPerFix = append(editsPerFix, &ImportFix{
			Fix:   fix,
			Edits: edits,
		})
	}
	return allFixEdits, editsPerFix, nil
}

// ComputeOneImportFixEdits returns text edits for a single import fix.
func ComputeOneImportFixEdits(snapshot Snapshot, pgf *ParsedGoFile, fix *imports.ImportFix) ([]protocol.TextEdit, error) {
	options := &imports.Options{
		LocalPrefix: snapshot.View().Options().Local,
		// Defaults.
		AllErrors:  true,
		Comments:   true,
		Fragment:   true,
		FormatOnly: false,
		TabIndent:  true,
		TabWidth:   8,
	}
	return computeFixEdits(snapshot, pgf, options, []*imports.ImportFix{fix})
}

func computeFixEdits(snapshot Snapshot, pgf *ParsedGoFile, options *imports.Options, fixes []*imports.ImportFix) ([]protocol.TextEdit, error) {
	// trim the original data to match fixedData
	left, err := importPrefix(pgf.Src)
	if err != nil {
		return nil, err
	}
	extra := !strings.Contains(left, "\n") // one line may have more than imports
	if extra {
		left = string(pgf.Src)
	}
	if len(left) > 0 && left[len(left)-1] != '\n' {
		left += "\n"
	}
	// Apply the fixes and re-parse the file so that we can locate the
	// new imports.
	flags := parser.ImportsOnly
	if extra {
		// used all of origData above, use all of it here too
		flags = 0
	}
	fixedData, err := imports.ApplyFixes(fixes, "", pgf.Src, options, flags)
	if err != nil {
		return nil, err
	}
	if fixedData == nil || fixedData[len(fixedData)-1] != '\n' {
		fixedData = append(fixedData, '\n') // ApplyFixes may miss the newline, go figure.
	}
	edits, err := snapshot.View().Options().ComputeEdits(pgf.URI, left, string(fixedData))
	if err != nil {
		return nil, err
	}
	return ProtocolEditsFromSource([]byte(left), edits, pgf.Mapper.Converter)
}

// importPrefix returns the prefix of the given file content through the final
// import statement. If there are no imports, the prefix is the package
// statement and any comment groups below it.
func importPrefix(src []byte) (string, error) {
	fset := token.NewFileSet()
	// do as little parsing as possible
	f, err := parser.ParseFile(fset, "", src, parser.ImportsOnly|parser.ParseComments)
	if err != nil { // This can happen if 'package' is misspelled
		return "", fmt.Errorf("importPrefix: failed to parse: %s", err)
	}
	tok := fset.File(f.Pos())
	var importEnd int
	for _, d := range f.Decls {
		if x, ok := d.(*ast.GenDecl); ok && x.Tok == token.IMPORT {
			if e, err := Offset(tok, d.End()); err != nil {
				return "", fmt.Errorf("importPrefix: %s", err)
			} else if e > importEnd {
				importEnd = e
			}
		}
	}

	maybeAdjustToLineEnd := func(pos token.Pos, isCommentNode bool) int {
		offset, err := Offset(tok, pos)
		if err != nil {
			return -1
		}

		// Don't go past the end of the file.
		if offset > len(src) {
			offset = len(src)
		}
		// The go/ast package does not account for different line endings, and
		// specifically, in the text of a comment, it will strip out \r\n line
		// endings in favor of \n. To account for these differences, we try to
		// return a position on the next line whenever possible.
		switch line := tok.Line(tok.Pos(offset)); {
		case line < tok.LineCount():
			nextLineOffset, err := Offset(tok, tok.LineStart(line+1))
			if err != nil {
				return -1
			}
			// If we found a position that is at the end of a line, move the
			// offset to the start of the next line.
			if offset+1 == nextLineOffset {
				offset = nextLineOffset
			}
		case isCommentNode, offset+1 == tok.Size():
			// If the last line of the file is a comment, or we are at the end
			// of the file, the prefix is the entire file.
			offset = len(src)
		}
		return offset
	}
	if importEnd == 0 {
		pkgEnd := f.Name.End()
		importEnd = maybeAdjustToLineEnd(pkgEnd, false)
	}
	for _, cgroup := range f.Comments {
		for _, c := range cgroup.List {
			if end, err := Offset(tok, c.End()); err != nil {
				return "", err
			} else if end > importEnd {
				startLine := tok.Position(c.Pos()).Line
				endLine := tok.Position(c.End()).Line

				// Work around golang/go#41197 by checking if the comment might
				// contain "\r", and if so, find the actual end position of the
				// comment by scanning the content of the file.
				startOffset, err := Offset(tok, c.Pos())
				if err != nil {
					return "", err
				}
				if startLine != endLine && bytes.Contains(src[startOffset:], []byte("\r")) {
					if commentEnd := scanForCommentEnd(src[startOffset:]); commentEnd > 0 {
						end = startOffset + commentEnd
					}
				}
				importEnd = maybeAdjustToLineEnd(tok.Pos(end), true)
			}
		}
	}
	if importEnd > len(src) {
		importEnd = len(src)
	}
	return string(src[:importEnd]), nil
}

// scanForCommentEnd returns the offset of the end of the multi-line comment
// at the start of the given byte slice.
func scanForCommentEnd(src []byte) int {
	var s scanner.Scanner
	s.Init(bytes.NewReader(src))
	s.Mode ^= scanner.SkipComments

	t := s.Scan()
	if t == scanner.Comment {
		return s.Pos().Offset
	}
	return 0
}

func computeTextEdits(ctx context.Context, snapshot Snapshot, pgf *ParsedGoFile, formatted string) ([]protocol.TextEdit, error) {
	_, done := event.Start(ctx, "source.computeTextEdits")
	defer done()

	edits, err := snapshot.View().Options().ComputeEdits(pgf.URI, string(pgf.Src), formatted)
	if err != nil {
		return nil, err
	}
	return ToProtocolEdits(pgf.Mapper, edits)
}

// ProtocolEditsFromSource converts text edits to LSP edits using the original
// source.
func ProtocolEditsFromSource(src []byte, edits []diff.TextEdit, converter span.Converter) ([]protocol.TextEdit, error) {
	m := lsppos.NewMapper(src)
	var result []protocol.TextEdit
	for _, edit := range edits {
		spn, err := edit.Span.WithOffset(converter)
		if err != nil {
			return nil, fmt.Errorf("computing offsets: %v", err)
		}
		startLine, startChar := m.Position(spn.Start().Offset())
		endLine, endChar := m.Position(spn.End().Offset())
		if startLine < 0 || endLine < 0 {
			return nil, fmt.Errorf("out of bound span: %v", spn)
		}

		pstart := protocol.Position{Line: uint32(startLine), Character: uint32(startChar)}
		pend := protocol.Position{Line: uint32(endLine), Character: uint32(endChar)}
		if pstart == pend && edit.NewText == "" {
			// Degenerate case, which may result from a diff tool wanting to delete
			// '\r' in line endings. Filter it out.
			continue
		}
		result = append(result, protocol.TextEdit{
			Range:   protocol.Range{Start: pstart, End: pend},
			NewText: edit.NewText,
		})
	}
	return result, nil
}

func ToProtocolEdits(m *protocol.ColumnMapper, edits []diff.TextEdit) ([]protocol.TextEdit, error) {
	if edits == nil {
		return nil, nil
	}
	result := make([]protocol.TextEdit, len(edits))
	for i, edit := range edits {
		rng, err := m.Range(edit.Span)
		if err != nil {
			return nil, err
		}
		result[i] = protocol.TextEdit{
			Range:   rng,
			NewText: edit.NewText,
		}
	}
	return result, nil
}

func FromProtocolEdits(m *protocol.ColumnMapper, edits []protocol.TextEdit) ([]diff.TextEdit, error) {
	if edits == nil {
		return nil, nil
	}
	result := make([]diff.TextEdit, len(edits))
	for i, edit := range edits {
		spn, err := m.RangeSpan(edit.Range)
		if err != nil {
			return nil, err
		}
		result[i] = diff.TextEdit{
			Span:    spn,
			NewText: edit.NewText,
		}
	}
	return result, nil
}
