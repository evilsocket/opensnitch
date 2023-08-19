package pkg

func init() { // used
	var p P
	_ = p.n
}

type T0 struct { // used
	m int // unused
	n int // used
}

type T1 struct { // used
	T0 // used
}

type P *T1 // used
