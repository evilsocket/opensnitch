package main

type state func() state // used

func a() state { // used
	return a
}

func main() { // used
	st := a
	_ = st()
}

type t1 struct{} // unused
type t2 struct{} // used
type t3 struct{} // used

func fn1() t1     { return t1{} } // unused
func fn2() (x t2) { return }      // used
func fn3() *t3    { return nil }  // used

func fn4() { // used
	const x = 1  // used
	const y = 2  // unused
	type foo int // unused
	type bar int // used

	_ = x
	_ = bar(0)
}

func init() { // used
	fn2()
	fn3()
	fn4()
}
