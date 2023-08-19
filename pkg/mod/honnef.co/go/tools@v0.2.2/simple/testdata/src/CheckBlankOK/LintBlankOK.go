package pkg

func fn() {
	var m map[int]int
	var ch chan int
	var fn func() (int, bool)

	x, _ := m[0] // want `unnecessary assignment to the blank identifier`
	x, _ = <-ch  // want `unnecessary assignment to the blank identifier`
	x, _ = fn()
	_ = x
}
