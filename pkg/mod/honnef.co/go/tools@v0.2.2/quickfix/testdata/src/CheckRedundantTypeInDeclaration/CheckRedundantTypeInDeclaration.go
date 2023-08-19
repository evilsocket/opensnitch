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
	var _ int = gen1()           // want `could omit type int`
	var a int = Y                // want `could omit type int`
	var b int = 1                // want `could omit type int`
	var c int = 1.0              // different default type
	var d MyInt = 1              // different default type
	var e io.ReadCloser = gen2() // want `could omit type io.ReadCloser`
	var f io.Reader = gen2()     // different interface type
	var g float64 = math.Pi      // want `could omit type float64`
	var h bool = true            // want `could omit type bool`
	var i string = ""            // want `could omit type string`
	var j MyInt = gen3()         // want `could omit type MyInt`

	_, _, _, _, _, _, _, _, _, _ = a, b, c, d, e, f, g, h, i, j
}
