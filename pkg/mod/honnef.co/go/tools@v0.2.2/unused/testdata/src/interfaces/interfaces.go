package pkg

type I interface { // used
	fn1() // used
}

type t struct{} // used

func (t) fn1() {} // used
func (t) fn2() {} // unused

func init() { // used
	_ = t{}
}

type I1 interface { // used
	Foo() // used
}

type I2 interface { // used
	Foo() // used
	bar() // used
}

type i3 interface { // unused
	foo()
	bar()
}

type t1 struct{} // used
type t2 struct{} // used
type t3 struct{} // used
type t4 struct { // used
	t3 // used
}

func (t1) Foo() {} // used
func (t2) Foo() {} // used
func (t2) bar() {} // used
func (t3) Foo() {} // used
func (t3) bar() {} // used

func Fn() { // used
	var v1 t1
	var v2 t2
	var v3 t3
	var v4 t4
	_ = v1
	_ = v2
	_ = v3
	var x interface{} = v4
	_ = x.(I2)
}
