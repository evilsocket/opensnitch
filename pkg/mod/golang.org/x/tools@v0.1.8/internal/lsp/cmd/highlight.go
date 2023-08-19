// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	"context"
	"flag"
	"fmt"
	"sort"

	"golang.org/x/tools/internal/lsp/protocol"
	"golang.org/x/tools/internal/span"
	"golang.org/x/tools/internal/tool"
)

// highlight implements the highlight verb for gopls.
type highlight struct {
	app *Application
}

func (r *highlight) Name() string      { return "highlight" }
func (r *highlight) Usage() string     { return "<position>" }
func (r *highlight) ShortHelp() string { return "display selected identifier's highlights" }
func (r *highlight) DetailedHelp(f *flag.FlagSet) {
	fmt.Fprint(f.Output(), `
Example:

  $ # 1-indexed location (:line:column or :#offset) of the target identifier
  $ gopls highlight helper/helper.go:8:6
  $ gopls highlight helper/helper.go:#53
`)
	f.PrintDefaults()
}

func (r *highlight) Run(ctx context.Context, args ...string) error {
	if len(args) != 1 {
		return tool.CommandLineErrorf("highlight expects 1 argument (position)")
	}

	conn, err := r.app.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.terminate(ctx)

	from := span.Parse(args[0])
	file := conn.AddFile(ctx, from.URI())
	if file.err != nil {
		return file.err
	}

	loc, err := file.mapper.Location(from)
	if err != nil {
		return err
	}

	p := protocol.DocumentHighlightParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: loc.URI},
			Position:     loc.Range.Start,
		},
	}
	highlights, err := conn.DocumentHighlight(ctx, &p)
	if err != nil {
		return err
	}

	var results []span.Span
	for _, h := range highlights {
		l := protocol.Location{Range: h.Range}
		s, err := file.mapper.Span(l)
		if err != nil {
			return err
		}
		results = append(results, s)
	}
	// Sort results to make tests deterministic since DocumentHighlight uses a map.
	sort.SliceStable(results, func(i, j int) bool {
		return span.Compare(results[i], results[j]) == -1
	})

	for _, s := range results {
		fmt.Println(s)
	}
	return nil
}
