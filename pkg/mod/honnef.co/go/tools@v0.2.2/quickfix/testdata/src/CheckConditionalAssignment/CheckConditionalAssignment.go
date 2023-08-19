package pkg

func foo() bool { return true }

var bar bool
var baz bool

func fn() {
	x := false // want `merge conditional assignment`
	if foo() || (bar && !baz) {
		x = true
	}

	x = false
	if foo() || (bar && !baz) {
		x = true
	}

	y := false
	if true {
		y = true
		println(y)
	}

	z := false
	if true {
		z = false
	}

	a := false
	if true {
		x = true
	}

	b := true // want `merge conditional assignment`
	if foo() || (bar && !baz) {
		b = false
	}

	c := false
	if true {
		c = false
	}

	d := true
	if true {
		d = true
	}

	_ = x
	_ = y
	_ = z
	_ = a
	_ = b
	_ = c
	_ = d
}
