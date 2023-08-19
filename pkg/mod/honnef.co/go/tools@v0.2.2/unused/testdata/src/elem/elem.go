// Test of field usage detection

package pkg

type t15 struct { // used
	f151 int // used
}
type a2 [1]t15 // used

type t16 struct{} // used
type a3 [1][1]t16 // used

func foo() { // used
	_ = a2{0: {1}}
	_ = a3{{{}}}
}

func init() { foo() } // used
