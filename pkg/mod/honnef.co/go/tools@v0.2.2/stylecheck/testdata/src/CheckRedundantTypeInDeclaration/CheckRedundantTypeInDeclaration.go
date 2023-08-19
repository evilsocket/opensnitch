package pkg

import (
	"io"
	"math"
)

type MyInt int

const X int = 1
const Y = 1

func gen1() int           { return 0 }
func gen2() io.ReadCloser { return nil }
func gen3() MyInt         { return 0 }

// don't flag global variables
var a int = gen1()

func fn() {
	var _ int = gen1()           // don't flag blank identifier
	var a int = Y                // don't flag named untyped constants
	var b int = 1                // want `should omit type int`
	var c int = 1.0              // different default type
	var d MyInt = 1              // different default type
	var e io.ReadCloser = gen2() // want `should omit type io.ReadCloser`
	var f io.Reader = gen2()     // different interface type
	var g float64 = math.Pi      // don't flag named untyped constants
	var h bool = true            // want `should omit type bool`
	var i string = ""            // want `should omit type string`
	var j MyInt = gen3()         // want `should omit type MyInt`

	_, _, _, _, _, _, _, _, _, _ = a, b, c, d, e, f, g, h, i, j
}
