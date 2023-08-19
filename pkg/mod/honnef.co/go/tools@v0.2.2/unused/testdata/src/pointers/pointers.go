package baz

import "fmt"

type Foo interface { // used
	bar() // used
}

func Bar(f Foo) { // used
	f.bar()
}

type Buzz struct{} // used

func (b *Buzz) bar() { // used
	fmt.Println("foo bar buzz")
}
