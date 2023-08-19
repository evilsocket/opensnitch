package main

import "net/http"

type t1 struct{} // used
type t2 struct{} // unused
type t3 struct{} // used

type alias1 = t1  // used
type alias2 = t2  // unused
type alias3 = t3  // used
type alias4 = int // used

func main() { // used
	var _ alias1
	var _ t3
}

type t4 struct { // used
	x int // used
}

func (t4) foo() {} // used

//lint:ignore U1000 alias5 is ignored, which also ignores t4
type alias5 = t4 // used

//lint:ignore U1000 alias6 is ignored, and we don't incorrectly try to include http.Server's fields and methods in the graph
type alias6 = http.Server // used

//lint:ignore U1000 aliases don't have to be to named types
type alias7 = struct { // used
	x int // used
}
