package pkg

import "fmt"

func fn1() {
	var s []int
	s = append(s, 1) // want `this result of append is never used`
	s = append(s, 1) // want `this result of append is never used`
}

func fn2() (named []int) {
	named = append(named, 1)
	return
}

func fn3() {
	s := make([]int, 0)
	s = append(s, 1) // want `this result of append is never used`
}

func fn3_1(n int) {
	s := make([]int, n)
	s = append(s, 1) // want `this result of append is never used`
}

func fn4() []int {
	var s []int
	s = append(s, 1)
	return s
}

func fn5() {
	var s []int
	s = append(s, 1)
	fn6(s)
}

func fn6([]int) {}

func fn7() {
	var s []int
	fn8(&s)
	s = append(s, 1)
}

func fn8(*[]int) {}

func fn9() {
	var s []int
	s = append(s, 1)
	fmt.Println(s)
	s = append(s, 1)
}

func fn10() {
	var s []int
	return
	s = append(s, 1)
}

func fn11() {
	var s []int
	for x := 0; x < 10; x++ {
		s = append(s, 1) // want `this result of append is never used`
	}
}

func fn12(a []int) {
	b := a[:0]
	for _, x := range a {
		if true {
			b = append(b, x)
		}
	}
}

func fn13() []byte {
	a := make([]byte, 10)
	b := a[:5]
	for i := 0; i < 2; i++ {
		a = append(a, 1)
	}
	return b
}

func fn14() []byte {
	a := make([]byte, 10)
	b := a[:5]
	for i := 0; i < 2; i++ {
		b = append(b, 1)
	}
	return a
}

func fn15() {
	s := make([]byte, 0, 1)
	retain(s)
	s = append(s, 1)
}

func fn16(s []byte) {
	for i := 0; i < 2; i++ {
		s = append(s, 1)
	}
}

func fn17(x *[5]byte) {
	s := x[:0]
	for i := 0; i < 2; i++ {
		s = append(s, 1)
	}
}

func fn18() {
	var x [4]byte
	s := x[:0]
	for i := 0; i < 2; i++ {
		s = append(s, 1)
	}
	_ = x
}

func fn19() [4]int {
	var x [4]int
	s := x[:]
	s = append(s, 1)
	return x
}

func fn20() {
	var x [4]int
	s := x[:]
	s = append(s, 1) // want `this result of append is never used`
}

func fn21() {
	var x []byte
	x = append(x, 1)
	retain(x)
	x = append(x, 2)
}

func fn22() {
	// we should probably flag this, but we currently don't
	var x1 []byte
	x2 := append(x1, 1)
	x2 = append(x2, 2)
	x3 := append(x1, 3)
	x3 = append(x3, 4)
}

func fn23(n int) []int {
	s := make([]int, 0, n)
	s2 := append(s, 1, 2, 3) // this can be observed by extending the capacity of x
	s2 = append(s2, 4)
	x := append(s, 2)
	return x
}

func fn24() []byte {
	x := make([]byte, 0, 24)
	s1 := append(x, 1)
	s2 := append(s1, 2)
	s2 = append(s2, 3)
	s3 := append(s1, 4)
	return s3
}

func fn25() {
	var s []byte
	if true {
		s = append(s, 1)
	}
	s = append(s, 2) // want `this result of append is never used`
}

func fn26() {
	var s []byte
	if true {
		s = append(s, 1)
		retain(s)
	}
	s = append(s, 2)
}

func fn27() {
	var s []byte
	if true {
		s = make([]byte, 0, 1)
	} else {
		s = make([]byte, 0, 2)
	}
	s = append(s, 1) // want `this result of append is never used`
}

func fn28() {
	var s []byte
	if true {
		s = make([]byte, 0, 1)
	} else {
		s = make([]byte, 0, 2)
		retain(s)
	}
	s = append(s, 1)
}

func fn29() {
	x := gen()
	x = append(x, 1)
}

func fn30(x T) {
	s := x.s
	s = append(s, 1)
}

var Global []int

func fn31() {
	Global = append(Global, 1)
}

type T struct {
	s []byte
}

func gen() []byte { return nil }

func retain([]byte) {}
