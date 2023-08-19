package pkg

import (
	"compress/flate"
	"unsafe"
)

type t1 struct { // used
	a int // used
	b int // used
}

type t2 struct { // used
	a int // used
	b int // used
}

type t3 struct { // used
	a int // used
	b int // unused
}

type t4 struct { // used
	a int // used
	b int // unused
}

type t5 struct { // used
	a int // used
	b int // used
}

type t6 struct { // used
	a int // used
	b int // used
}

type t7 struct { // used
	a int // used
	b int // used
}

type t8 struct { // used
	a int // used
	b int // used
}

type t9 struct { // used
	Offset int64 // used
	Err    error // used
}

type t10 struct { // used
	a int // used
	b int // used
}

func fn() { // used
	// All fields in t2 used because they're initialised in t1
	v1 := t1{0, 1}
	v2 := t2(v1)
	_ = v2

	// Field b isn't used by anyone
	v3 := t3{}
	v4 := t4(v3)
	println(v3.a)
	_ = v4

	// Both fields are used
	v5 := t5{}
	v6 := t6(v5)
	println(v5.a)
	println(v6.b)

	v7 := &t7{}
	println(v7.a)
	println(v7.b)
	v8 := (*t8)(v7)
	_ = v8

	vb := flate.ReadError{}
	v9 := t9(vb)
	_ = v9

	// All fields are used because this is an unsafe conversion
	var b []byte
	v10 := (*t10)(unsafe.Pointer(&b[0]))
	_ = v10
}

func init() { fn() } // used
