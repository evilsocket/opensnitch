package pkg

type t1 struct { // used
	a int // used
	b int // unused
}

type t2 struct { // used
	a int // unused
	b int // used
}

func Fn() { // used
	x := t1{}
	y := t2{}
	println(x.a)
	println(y.b)
}
