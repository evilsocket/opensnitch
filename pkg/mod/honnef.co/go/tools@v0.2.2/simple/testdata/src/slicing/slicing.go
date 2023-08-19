package pkg

func fn() {
	var s [5]int
	_ = s[:len(s)] // want `omit second index`

	len := func(s [5]int) int { return -1 }
	_ = s[:len(s)]
}
