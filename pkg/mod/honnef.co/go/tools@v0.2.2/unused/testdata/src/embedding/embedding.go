package pkg

type I interface { // used
	f1() // used
	f2() // used
}

func init() { // used
	var _ I
}

type t1 struct{} // used
type T2 struct { // used
	t1 // used
}

func (t1) f1() {} // used
func (T2) f2() {} // used

func Fn() { // used
	var v T2
	_ = v.t1
}

type I2 interface { // used
	f3() // used
	f4() // used
}

type t3 struct{} // used
type t4 struct { // used
	x  int // unused
	y  int // unused
	t3     // used
}

func (*t3) f3() {} // used
func (*t4) f4() {} // used

func init() { // used
	var i I2 = &t4{}
	i.f3()
	i.f4()
}

type i3 interface { // used
	F() // used
}

type I4 interface { // used
	i3
}

type T5 struct { // used
	t6 // used
}

type t6 struct { // used
	F int // used
}

type t7 struct { // used
	X int // used
}
type t8 struct { // used
	t7 // used
}
type t9 struct { // used
	t8 // used
}

var _ = t9{}

type t10 struct{} // used

func (*t10) Foo() {} // used

type t11 struct { // used
	t10 // used
}

var _ = t11{}

type i5 interface{} // used
type I6 interface { // used
	i5
}
