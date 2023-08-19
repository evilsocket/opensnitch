package pkg

func fn() {
	var x, y int
	var z []int
	var a bool

	if x == 1 || x == 2 { // want `could use tagged switch on x`
	} else if x == 3 {
	}

	if x == 1 || x == 2 { // want `could use tagged switch on x`
	} else if x == 3 {
	} else {
	}

	if x == 1 || x == 2 {
	} else if y == 3 {
	} else {
	}

	if a == (x == y) { // want `could use tagged switch on a`
	} else if a == (x != y) {
	}

	if z[0] == 1 || z[0] == 2 { // want `could use tagged switch on z\[0\]`
	} else if z[0] == 3 {
	}

	for {
		if x == 1 || x == 2 { // want `could use tagged switch on x`
		} else if x == 3 {
		}
	}

	for {
		if x == 1 || x == 2 {
		} else if x == 3 {
			break
		}
	}

	if x == 1 || x == 2 {
	}
}
