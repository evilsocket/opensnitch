package pkg

var a byte     // used
var b [16]byte // used

type t1 struct{} // used
type t2 struct{} // used
type t3 struct{} // used
type t4 struct{} // used
type t5 struct{} // used

type iface interface{} // used

var x t1           // used
var y = t2{}       // used
var j = t3{}       // used
var k = t4{}       // used
var l iface = t5{} // used

func Fn() { // used
	println(a)
	_ = b[:]

	_ = x
	_ = y
	_ = j
	_ = k
	_ = l
}
