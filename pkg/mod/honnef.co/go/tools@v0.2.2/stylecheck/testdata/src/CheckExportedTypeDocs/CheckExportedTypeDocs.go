package pkg

// Some type
type t1 struct{}

// Some type // want `comment on exported type`
type T2 struct{}

// T3 is amazing
type T3 struct{}

type (
	// Some type // want `comment on exported type`
	T4 struct{}
	// The T5 type is amazing
	T5 struct{}
	// Some type
	t6 struct{}
)

// Some types
type (
	T7 struct{}
	T8 struct{}
)

// Some types
type (
	T9 struct{}
)

func fn() {
	// Some type
	type T1 struct{}
}

//
type T10 struct{} // this is fine, because "no comment" and "empty comment" are treated the same

//
// T11 is amazing.
//
// godoc allows this style, because ast.CommentGroup.Text strips whitespace.
// We currently make no effort to flag it.
//
type T11 struct{}

//some:directive
type T12 struct{} // we pretend that directives aren't part of the doc string, just like godoc in Go 1.15+ does

//some:directive
// T13 is amazing
type T13 struct{}

//some:directive // want `comment on exported type`
// Whatever
type T14 struct{}
