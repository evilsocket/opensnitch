package pkg

func fn1(t struct { // used
	a int // used
	b int // used
}) {
	fn2(t)
}

func fn2(t struct { // used
	a int // used
	b int // used
}) {
	println(t.a)
	println(t.b)
}

func Fn() { // used
	fn1(struct {
		a int // used
		b int // used
	}{1, 2})
}
