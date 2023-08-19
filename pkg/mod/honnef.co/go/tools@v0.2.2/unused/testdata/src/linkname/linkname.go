package pkg

import _ "unsafe"

//other:directive
//go:linkname ol other4

//go:linkname foo other1
func foo() {} // used

//go:linkname bar other2
var bar int // used

var (
	baz int // unused
	//go:linkname qux other3
	qux int // used
)

//go:linkname fisk other3
var (
	fisk int // used
)

var ol int // used

//go:linkname doesnotexist other5
