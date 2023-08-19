package pkg

// Whatever
var a int

// Whatever // want `should be of the form`
var B int

// Whatever
var (
	// Whatever
	C int
)

func fn() {
	// Whatever
	var D int
	_ = D
}

//
var E int // this is fine, because "no comment" and "empty comment" are treated the same

//
// F is amazing.
//
// godoc allows this style, because ast.CommentGroup.Text strips whitespace.
// We currently make no effort to flag it.
//
var F int

//some:directive
var G int // we pretend that directives aren't part of the doc string, just like godoc in Go 1.15+ does

//some:directive
// H is amazing
var H int

//some:directive // want `should be of the form`
// Whatever
var I int
