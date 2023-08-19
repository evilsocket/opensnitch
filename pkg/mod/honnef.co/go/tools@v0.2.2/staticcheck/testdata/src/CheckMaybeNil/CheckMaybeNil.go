package pkg

import (
	"os"
	"syscall"
)

func fn1(x *int) {
	_ = *x // want `possible nil pointer dereference`
	if x != nil {
		return
	}
	println()
}

func fn1_1(x *int) {
	// this doesn't get flagged because the conditional return gets optimized away
	_ = *x
	if x != nil {
		return
	}
}

func fn2(x *int) {
	if x == nil {
		println("we should return")
	}
	_ = *x // want `possible nil pointer dereference`
}

func fn3(x *int) {
	if x != nil {
		_ = *x
	}
}

func fn4(x *int) {
	if x == nil {
		x = gen()
	}
	_ = *x
}

func fn5(x *int) {
	if x == nil {
		x = gen()
	}
	_ = *x // want `possible nil pointer dereference`
	if x == nil {
		println("we should return")
	}
}

func fn6() {
	x := new(int)
	if x == nil {
		println("we should return")
	}
	// x can't be nil
	_ = *x
}

func fn7() {
	var x int
	y := &x
	if y == nil {
		println("we should return")
	}
	// y can't be nil
	_ = *y
}

func fn8(x *int) {
	if x == nil {
		return
	}
	// x can't be nil
	_ = *x
}

func fn9(x *int) {
	if x != nil {
		return
	}
	// TODO(dh): not currently supported
	_ = *x
}

func gen() *int { return nil }

func die1(b bool) {
	if b {
		println("yay")
		os.Exit(0)
	} else {
		println("nay")
		os.Exit(1)
	}
}

func die2(b bool) {
	if b {
		println("yay")
		os.Exit(0)
	}
}

func fn10(x *int) {
	if x == nil {
		die1(true)
	}
	_ = *x
}

func fn11(x *int) {
	if x == nil {
		die2(true)
	}
	_ = *x // want `possible nil pointer dereference`
}

func doPanic() { panic("") }
func doExit()  { syscall.Exit(1) }

func fn12(arg bool) {
	if arg {
		doPanic()
	} else {
		doExit()
	}
}

func fn13(arg bool) {
	fn12(arg)
}

func fn14(x *int) {
	if x == nil {
		fn13(true)
	}
	_ = *x
}

func assert(b bool) {
	if b {
		panic("meh")
	}
}

func fn15(x *int) {
	assert(x != nil)
	_ = *x
}

func fn16() {
	var xs []int
	if xs == nil {
		println()
	}

	for _, x := range xs {
		_ = x
	}

	var xs2 *[1]int
	if xs2 == nil {
		println()
	}
	for _, x := range xs2 { // want `possible nil pointer dereference`
		_ = x
	}

	var xs3 *[]int
	if xs3 == nil {
		println()
	}
	for _, x := range *xs3 { // want `possible nil pointer dereference`
		_ = x
	}

	var xs4 []int
	if xs4 == nil {
		println()
	}
	_ = xs4[0]
}
