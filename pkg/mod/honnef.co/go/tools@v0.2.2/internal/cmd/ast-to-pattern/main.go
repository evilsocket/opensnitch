package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"io/ioutil"
	"os"

	"honnef.co/go/tools/pattern"
)

func main() {
	src, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fset := token.NewFileSet()
	node, err := parseDetectingNode(fset, string(src))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if _, ok := node.(*ast.File); ok {
		fmt.Fprintln(os.Stderr, "cannot convert entire file to Node")
		os.Exit(1)
	}
	fmt.Println(pattern.ASTToNode(node))
}
