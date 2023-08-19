package pkg

type t1 struct{} // used
type t2 struct { // used
	t3 // used
}
type t3 struct{} // used

func (t1) Foo() {} // used
func (t3) Foo() {} // used
func (t3) foo() {} // unused

func init() { // used
	_ = t1{}
	_ = t2{}
}
