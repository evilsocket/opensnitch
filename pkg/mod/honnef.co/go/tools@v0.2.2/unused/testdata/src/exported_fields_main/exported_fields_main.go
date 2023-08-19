package main

type t1 struct { // used
	F1 int // used
}

type T2 struct { // used
	F2 int // used
}

func init() { // used
	_ = t1{}
	_ = T2{}
}
