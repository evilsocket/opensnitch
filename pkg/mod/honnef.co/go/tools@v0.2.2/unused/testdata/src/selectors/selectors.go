package pkg

type t struct { // used
	f int // used
}

func fn(v *t) { // used
	println(v.f)
}

func init() { // used
	var v t
	fn(&v)
}
