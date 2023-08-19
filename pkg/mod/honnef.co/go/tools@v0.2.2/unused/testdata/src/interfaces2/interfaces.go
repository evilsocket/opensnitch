package pkg

type I interface { // used
	foo() // used
}

type T struct{} // used

func (T) foo() {} // used
func (T) bar() {} // unused

var _ struct {
	T // used
}
