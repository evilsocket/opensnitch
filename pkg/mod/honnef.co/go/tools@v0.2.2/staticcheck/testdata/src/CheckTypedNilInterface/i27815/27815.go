package main

import (
	"fmt"
)

type MyError struct {
	x string
}

func (e *MyError) Error() string {
	return e.x
}

func f() *MyError {
	return nil
}

func main() {
	var e error
	e = f()
	// e should be nil ?
	if e != nil { // want `this comparison is always true`
		fmt.Println("NOT NIL")
	} else {
		fmt.Println("NIL")
	}
}
