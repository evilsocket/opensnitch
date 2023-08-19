package main

type AA interface { // used
	A() // used
}

type BB interface { // used
	AA
}

type CC interface { // used
	BB
	C() // used
}

func c(cc CC) { // used
	cc.A()
}

type z struct{} // used

func (z) A() {} // used
func (z) B() {} // used
func (z) C() {} // used

func main() { // used
	c(z{})
}
