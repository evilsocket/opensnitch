package pkg

import "fmt"

type Node interface { // used
	position() int // used
}

type noder struct{} // used

func (noder) position() int { panic("unreachable") } // used

func Fn() { // used
	nodes := []Node{struct {
		noder // used
	}{}}
	fmt.Println(nodes)
}
