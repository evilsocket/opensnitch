package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"honnef.co/go/tools/pattern"
)

func match(fset *token.FileSet, pat pattern.Pattern, f *ast.File) {
	ast.Inspect(f, func(node ast.Node) bool {
		if node == nil {
			return true
		}

		for _, rel := range pat.Relevant {
			if rel == reflect.TypeOf(node) {
				m := &pattern.Matcher{}
				if m.Match(pat.Root, node) {
					fmt.Printf("%s: ", fset.Position(node.Pos()))
					format.Node(os.Stdout, fset, node)
					fmt.Println()
				}

				// OPT(dh): we could further speed this up by not
				// chasing down impossible subtrees. For example,
				// we'll never find an ImportSpec beneath a FuncLit.
				return true
			}
		}
		return true
	})

}

func main() {
	flag.Parse()
	// XXX don't use MustParse, handle error
	p := &pattern.Parser{}
	q, err := p.Parse(flag.Args()[0])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dir := flag.Args()[1]
	// XXX should we create a new fileset per file? what if we're
	// checking millions of files, will this use up a lot of memory?
	fset := token.NewFileSet()
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// XXX error handling
			panic(err)
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// XXX don't try to parse irregular files or directories
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			// XXX log error?
			return nil
		}

		match(fset, q, f)

		return nil
	})
}
