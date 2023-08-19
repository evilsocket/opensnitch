package pkg

func fn(x int, y *int) {
	_ = &x == nil // want `the address of a variable cannot be nil`
	_ = &y != nil // want `the address of a variable cannot be nil`

	if &x != nil { // want `the address of a variable cannot be nil`
		println("obviously.")
	}

	if y == nil {
	}
}
