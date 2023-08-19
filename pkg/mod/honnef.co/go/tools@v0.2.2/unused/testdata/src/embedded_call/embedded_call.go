package pkg

var t1 struct { // used
	t2 // used
	t3 // used
	t4 // used
}

type t2 struct{} // used
type t3 struct{} // used
type t4 struct { // used
	t5 // used
}
type t5 struct{} // used

func (t2) foo() {} // used
func (t3) bar() {} // used
func (t5) baz() {} // used
func init() { // used
	t1.foo()
	_ = t1.bar
	t1.baz()
}
