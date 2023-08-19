package pkg

type t1 struct { // used
	F1 int // used
}

type T2 struct { // used
	F2 int // used
}

var v struct { // used
	T3 // used
}

type T3 struct{} // used

func (T3) Foo() {} // used

func init() { // used
	v.Foo()
}

func init() { // used
	_ = t1{}
}

type codeResponse struct { // used
	Tree *codeNode `json:"tree"` // used
}

type codeNode struct { // used
}

func init() { // used
	_ = codeResponse{}
}
