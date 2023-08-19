package pkg

func fn(x int) {
	var z int
	var y int
	x = x             // want `self-assignment`
	y = y             // want `self-assignment`
	y, x, z = y, x, 1 // want `self-assignment of y to y` `self-assignment of x to x`
	y = x
	_ = y
	_ = x
	_ = z
	func() {
		x := x
		println(x)
	}()
}

func fn1() {
	var (
		x  []byte
		ch chan int
	)
	x[42] = x[42]                         // want `self-assignment`
	x[pure(42)] = x[pure(42)]             // want `self-assignment`
	x[pure(pure(42))] = x[pure(pure(42))] // want `self-assignment`
	x[impure(42)] = x[impure(42)]
	x[impure(pure(42))] = x[impure(pure(42))]
	x[pure(impure(42))] = x[pure(impure(42))]
	x[pure(<-ch)] = x[pure(<-ch)]
	x[pure(pure(<-ch))] = x[pure(pure(<-ch))]
	x[<-ch] = x[<-ch]

	type T struct {
		x []int
	}
	var ts []T
	ts[impure(42)].x = ts[impure(42)].x
	m := map[*int]int{}
	m[ptr1()] = m[ptr1()]
	m[ptr2()] = m[ptr2()]
	m[new(int)] = m[new(int)]

	m2 := map[int]int{}
	m2[len(x)] = m2[len(x)] // want `self-assignment`

	gen1()[0] = gen1()[0]
	gen2(0)[0] = gen2(0)[0] // want `self-assignment`
	gen3(0)[0] = gen3(0)[0]
}

func ptr1() *int {
	return new(int)
}

func ptr2() *int {
	x := 0
	return &x
}

func gen1() []int {
	return nil
}

func gen2(x int) []int {
	return nil
}

func gen3(x int) []int {
	return make([]int, 0)
}

func pure(n int) int {
	return n
}

func impure(n int) int {
	println(n)
	return n
}
