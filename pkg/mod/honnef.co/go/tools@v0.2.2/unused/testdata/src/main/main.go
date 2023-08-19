package main

func Fn1() {} // used
func Fn2() {} // used
func fn3() {} // unused

const X = 1 // used

var Y = 2 // used

type Z struct{} // used

func main() { // used
	Fn1()
}
