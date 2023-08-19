package pkg

func fn1() {
	var foo []int

	if len(foo) < 0 { // want `len does not return negative values`
		println("test")
	}

	switch {
	case len(foo) < 0: // want `negative`
		println("test")
	}

	for len(foo) < 0 { // want `negative`
		println("test")
	}

	println(len(foo) < 0) // want `negative`

	if 0 > cap(foo) { // want `cap does not return negative values`
		println("test")
	}

	switch {
	case 0 > cap(foo): // want `negative`
		println("test")
	}

	for 0 > cap(foo) { // want `negative`
		println("test")
	}

	println(0 > cap(foo)) // want `negative`
}

func fn2() {
	const zero = 0
	var foo []int
	println(len(foo) < zero)
	println(len(foo) < 1)
}
