package pkg

func fn() {
	var m map[string]int

	// with :=
	for x, _ := range m { // want `unnecessary assignment to the blank identifier`
		_ = x
	}
	// with =
	var y string
	_ = y
	for y, _ = range m { // want `unnecessary assignment to the blank identifier`
	}

	for _ = range m { // want `unnecessary assignment to the blank identifier`
	}

	for _, _ = range m { // want `unnecessary assignment to the blank identifier`
	}

	// all OK:
	for x := range m {
		_ = x
	}
	for x, y := range m {
		_, _ = x, y
	}
	for _, y := range m {
		_ = y
	}
	var x int
	_ = x
	for y = range m {
	}
	for y, x = range m {
	}
	for _, x = range m {
	}
}
