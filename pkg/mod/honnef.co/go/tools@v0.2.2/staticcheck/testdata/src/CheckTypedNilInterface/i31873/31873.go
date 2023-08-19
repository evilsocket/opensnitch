package main

import "fmt"

type S struct{}

func (s *S) Error() string {
	return "error for S"
}

func structNil() *S {
	return nil
}

func errorNil() error {
	return nil
}

func main() {
	err := errorNil()
	fmt.Println(err != nil)
	err = structNil()
	fmt.Println(err != nil) // want `this comparison is always true`
	err = errorNil()
	fmt.Println(err != nil)
}
