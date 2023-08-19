package pkg

import "fmt"

type i1 interface {
	String() int
}

type i2 interface {
	String() string
}

type i3 interface {
	bar() int
}

type i4 interface {
	String() int
	bar() int
}

func fn() {
	var v1 i1
	_ = v1.(i2) // want `impossible type assertion; i1 and i2 contradict each other`
	_ = v1.(i3)
	_ = v1.(i4)
	_ = v1.(fmt.Stringer) // want `impossible type assertion; i1 and fmt.Stringer contradict each other`
	_ = v1.(interface {   // want `i1 and.+String.+contradict each other`
		String() string
	})
}
