package main

import (
	"errors"
	"fmt"
)

func main() {
	var err = errors.New("errors msg")
	name, err := GetName()
	if err != nil { // want `this comparison is always true`
		fmt.Println(err)
	} else {
		fmt.Println(name)
	}
}

type Error struct {
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return "Error is nil"
	}
	return e.Message
}

func GetName() (string, *Error) {
	var err = &Error{
		Message: "error msg",
	}
	err = nil
	return "yixinin", err
}
