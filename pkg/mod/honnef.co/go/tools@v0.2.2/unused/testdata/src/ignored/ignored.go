package pkg

//lint:ignore U1000 consider yourself used
type t1 struct{} // used
type t2 struct{} // used
type t3 struct{} // used

func (t1) fn1() {} // used
func (t1) fn2() {} // used
func (t1) fn3() {} // used

//lint:ignore U1000 be gone
func (t2) fn1() {} // used
func (t2) fn2() {} // unused
func (t2) fn3() {} // unused

func (t3) fn1() {} // unused
func (t3) fn2() {} // unused
func (t3) fn3() {} // unused

//lint:ignore U1000 consider yourself used
func fn() { // used
	var _ t2
	var _ t3
}

//lint:ignore U1000 bye
type t4 struct { // used
	x int // used
}

func (t4) bar() {} // used

//lint:ignore U1000 consider yourself used
type t5 map[int]struct { // used
	y int // used
}

//lint:ignore U1000 consider yourself used
type t6 interface { // used
	foo() // used
}

//lint:ignore U1000 consider yourself used
type t7 = struct { // used
	z int // used
}

//lint:ignore U1000 consider yourself used
type t8 struct{} // used

func (t8) fn() { // used
	otherFn()
}

func otherFn() {} // used
