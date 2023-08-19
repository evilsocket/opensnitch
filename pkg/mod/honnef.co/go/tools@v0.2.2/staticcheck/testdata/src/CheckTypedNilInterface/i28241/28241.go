package main

import (
	"fmt"
	"reflect"
)

type Nil interface {
	String() string
}

func MakeNil() Nil {
	var n *NilStruct
	return n
}

type NilStruct struct {
	Data string
}

func (n *NilStruct) String() string {
	return n.Data
}

func main() {
	var n *NilStruct
	fmt.Printf("%t %#v %s %t\n",
		n == nil,
		n,
		reflect.ValueOf(n).Kind(),
		reflect.ValueOf(n).IsNil())
	n2 := MakeNil()
	fmt.Printf("%t %#v %s %t\n",
		n2 == nil, // want `this comparison is never true`
		n2,
		reflect.ValueOf(n2).Kind(),
		reflect.ValueOf(n2).IsNil())
	fmt.Println(n2.String())
}
