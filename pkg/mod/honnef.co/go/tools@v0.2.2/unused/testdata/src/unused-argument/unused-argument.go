package main

type t1 struct{} // used
type t2 struct{} // used

func (t1) foo(arg *t2) {} // used

func init() { // used
	t1{}.foo(nil)
}
