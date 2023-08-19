package pkg

func foo() int { return 0 }

func fn1() {
	var x, y int
	var z map[string][]int
	var a bool

	switch { // want `could use tagged switch on x`
	case x == 4: // comment
	case x == 1 || x == 2, x == 3:
	}

	switch { // want `could use tagged switch on x`
	case x == 1 || x == 2, x == 3:
	case x == 4:
	default:
	}

	switch { // want `could use tagged switch on z\[""\]\[0\]`
	case z[""][0] == 1 || z[""][0] == 2:
	}

	switch { // want `could use tagged switch on a`
	case a == (x == y) || a == (x != y):
	}

	switch {
	case z[""][0] == 1 || z[""][1] == 2:
	}

	switch {
	case x == 1 || x == 2, y == 3:
	case x == 4:
	default:
	}

	switch {
	case x == 1 || x == 2, x == 3:
	case y == 4:
	}

	switch {
	case x == 1 || x == 2, x == foo():
	case x == 4:
	default:
	}

	switch {
	}

	switch {
	default:
	}

	switch {
	case x == 1 && x == 2:
	}
}
