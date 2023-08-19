package main

import (
	"fmt"
	"os"
)

type CustomError struct {
	Err string
}

func (ce CustomError) Error() string {
	return ce.Err
}

func SomeFunc() (string, *CustomError) {
	return "hello", nil
}

func main() {
	// Do something that creates a variable err of type error
	_, err := os.Open("/")
	if err != nil {
		panic(err)
	}

	// Then replace the err type with *CustomError
	val, err := SomeFunc()
	if err != nil { // want `this comparison is always true`
		panic(err)
	}

	fmt.Println("No problem", val)
}
