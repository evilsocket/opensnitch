// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"

	"golang.org/x/tools/internal/lsp/diff"
	"golang.org/x/tools/internal/lsp/protocol"
	"golang.org/x/tools/internal/lsp/source"
	"golang.org/x/tools/internal/span"
	"golang.org/x/tools/internal/tool"
	errors "golang.org/x/xerrors"
)

// suggestedFix implements the fix verb for gopls.
type suggestedFix struct {
	Diff  bool `flag:"d" help:"display diffs instead of rewriting files"`
	Write bool `flag:"w" help:"write result to (source) file instead of stdout"`
	All   bool `flag:"a" help:"apply all fixes, not just preferred fixes"`

	app *Application
}

func (s *suggestedFix) Name() string      { return "fix" }
func (s *suggestedFix) Usage() string     { return "<filename>" }
func (s *suggestedFix) ShortHelp() string { return "apply suggested fixes" }
func (s *suggestedFix) DetailedHelp(f *flag.FlagSet) {
	fmt.Fprintf(f.Output(), `
Example: apply suggested fixes for this file:

  $ gopls fix -w internal/lsp/cmd/check.go

gopls fix flags are:
`)
	f.PrintDefaults()
}

// Run performs diagnostic checks on the file specified and either;
// - if -w is specified, updates the file in place;
// - if -d is specified, prints out unified diffs of the changes; or
// - otherwise, prints the new versions to stdout.
func (s *suggestedFix) Run(ctx context.Context, args ...string) error {
	if len(args) < 1 {
		return tool.CommandLineErrorf("fix expects at least 1 argument")
	}
	conn, err := s.app.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.terminate(ctx)

	from := span.Parse(args[0])
	uri := from.URI()
	file := conn.AddFile(ctx, uri)
	if file.err != nil {
		return file.err
	}

	if err := conn.diagnoseFiles(ctx, []span.URI{uri}); err != nil {
		return err
	}
	conn.Client.filesMu.Lock()
	defer conn.Client.filesMu.Unlock()

	codeActionKinds := []protocol.CodeActionKind{protocol.QuickFix}
	if len(args) > 1 {
		codeActionKinds = []protocol.CodeActionKind{}
		for _, k := range args[1:] {
			codeActionKinds = append(codeActionKinds, protocol.CodeActionKind(k))
		}
	}

	rng, err := file.mapper.Range(from)
	if err != nil {
		return err
	}
	p := protocol.CodeActionParams{
		TextDocument: protocol.TextDocumentIdentifier{
			URI: protocol.URIFromSpanURI(uri),
		},
		Context: protocol.CodeActionContext{
			Only:        codeActionKinds,
			Diagnostics: file.diagnostics,
		},
		Range: rng,
	}
	actions, err := conn.CodeAction(ctx, &p)
	if err != nil {
		return errors.Errorf("%v: %v", from, err)
	}
	var edits []protocol.TextEdit
	for _, a := range actions {
		if a.Command != nil {
			return fmt.Errorf("ExecuteCommand is not yet supported on the command line")
		}
		if !a.IsPreferred && !s.All {
			continue
		}
		if !from.HasPosition() {
			for _, c := range a.Edit.DocumentChanges {
				if fileURI(c.TextDocument.URI) == uri {
					edits = append(edits, c.Edits...)
				}
			}
			continue
		}
		// If the span passed in has a position, then we need to find
		// the codeaction that has the same range as the passed in span.
		for _, diag := range a.Diagnostics {
			spn, err := file.mapper.RangeSpan(diag.Range)
			if err != nil {
				continue
			}
			if span.ComparePoint(from.Start(), spn.Start()) == 0 {
				for _, c := range a.Edit.DocumentChanges {
					if fileURI(c.TextDocument.URI) == uri {
						edits = append(edits, c.Edits...)
					}
				}
				break
			}
		}

		// If suggested fix is not a diagnostic, still must collect edits.
		if len(a.Diagnostics) == 0 {
			for _, c := range a.Edit.DocumentChanges {
				if fileURI(c.TextDocument.URI) == uri {
					edits = append(edits, c.Edits...)
				}
			}
		}
	}

	sedits, err := source.FromProtocolEdits(file.mapper, edits)
	if err != nil {
		return errors.Errorf("%v: %v", edits, err)
	}
	newContent := diff.ApplyEdits(string(file.mapper.Content), sedits)

	filename := file.uri.Filename()
	switch {
	case s.Write:
		if len(edits) > 0 {
			ioutil.WriteFile(filename, []byte(newContent), 0644)
		}
	case s.Diff:
		diffs := diff.ToUnified(filename+".orig", filename, string(file.mapper.Content), sedits)
		fmt.Print(diffs)
	default:
		fmt.Print(string(newContent))
	}
	return nil
}
