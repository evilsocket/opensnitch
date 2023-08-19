package debug

import (
	"fmt"
	"go/token"

	"golang.org/x/tools/go/analysis"
)

type Positioner interface {
	Pos() token.Pos
}

func PrintPosition(pass *analysis.Pass, obj Positioner) {
	fmt.Println(pass.Fset.PositionFor(obj.Pos(), false))
}
