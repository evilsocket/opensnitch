package main

import (
	"errors"
	"fmt"
)

type someError struct {
	Msg string
}

func (e *someError) Error() string {
	return "someError: " + e.Msg
}

func calculate() (int, *someError) {
	return 42, nil
}

func main() {
	err := errors.New("ERROR")
	num, err := calculate()
	fmt.Println(num, err, err == nil) // want `this comparison is never true`
}
