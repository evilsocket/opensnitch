package pkg

type String string

func fn(s string, s2 String) {
	for _, r := range s {
		println(r)
	}

	for _, r := range []rune(s) { // want `should range over string`
		println(r)
	}

	for i, r := range []rune(s) {
		println(i)
		println(r)
	}

	x := []rune(s)
	for _, r := range x { // want `should range over string`
		println(r)
	}

	y := []rune(s)
	for _, r := range y {
		println(r)
	}
	println(y[0])

	for _, r := range []rune(s2) { // want `should range over string`
		println(r)
	}
}
