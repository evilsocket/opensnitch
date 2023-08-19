package pkg

import _ "fmt"

type t1 struct{} // unused
type t2 struct { // used
	_ int // used
}
type t3 struct{} // used
type t4 struct{} // used
type t5 struct{} // used

var _ = t2{}

func fn1() { // unused
	_ = t1{}
	var _ = t1{}
}

func fn2() { // used
	_ = t3{}
	var _ t4
	var _ *t5 = nil
}

func init() { // used
	fn2()
}

func _() {}

type _ struct{}
