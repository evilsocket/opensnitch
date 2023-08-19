package pkg

type iface interface { // unused
	foo()
}

type t1 struct{} // unused
func (t1) foo()  {} // unused

type t2 struct{} // used

func (t t2) bar(arg int) (ret int) { return 0 } // unused

func init() { // used
	_ = t2{}
}

type t3 struct { // unused
	a int
	b int
}

type T struct{} // used

func fn1() { // unused
	meh := func(arg T) {
	}
	meh(T{})
}

type localityList []int // unused

func (l *localityList) Fn1() {} // unused
func (l *localityList) Fn2() {} // unused
