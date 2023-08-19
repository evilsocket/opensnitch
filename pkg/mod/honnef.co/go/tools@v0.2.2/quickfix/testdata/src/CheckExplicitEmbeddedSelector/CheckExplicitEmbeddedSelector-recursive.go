package pkg

type T1 struct {
	Next *T1
}

type T2 struct {
	F int
	*T2
	T3
}

type T3 struct {
	F2 int
}

func (*T1) Foo() {}
func (*T2) Foo() {}

func fn() {
	var t1 T1
	var t2 T2
	_ = t1.Next.Foo
	_ = t2.T2.Foo
	_ = t2.T2.F
	_ = t2.T3.F2 // want `could remove embedded field "T3" from selector`
}
