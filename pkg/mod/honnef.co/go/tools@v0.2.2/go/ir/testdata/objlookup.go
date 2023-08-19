//+build ignore

package main

// This file is the input to TestObjValueLookup in source_test.go,
// which ensures that each occurrence of an ident defining or
// referring to a func, var or const object can be mapped to its
// corresponding IR Value.
//
// For every reference to a var object, we use annotations in comments
// to denote both the expected IR Value kind, and whether to expect
// its value (x) or its address (&x).
//
// For const and func objects, the results don't vary by reference and
// are always values not addresses, so no annotations are needed.  The
// declaration is enough.

import (
	"fmt"
	"os"
)

type J int

func (*J) method() {}

const globalConst = 0

var globalVar int //@ ir(globalVar,"&Global")

func globalFunc() {}

type I interface {
	interfaceMethod()
}

type S struct {
	x int //@ ir(x,"nil")
}

func main() {
	print(globalVar) //@ ir(globalVar,"Load")
	globalVar = 1    //@ ir(globalVar,"Const")

	var v0 int = 1 //@ ir(v0,"Const") // simple local value spec
	if v0 > 0 {    //@ ir(v0,"Const")
		v0 = 2 //@ ir(v0,"Const")
	}
	print(v0) //@ ir(v0,"Phi")

	// v1 is captured and thus implicitly address-taken.
	var v1 int = 1         //@ ir(v1,"Const")
	v1 = 2                 //@ ir(v1,"Const")
	fmt.Println(v1)        //@ ir(v1,"Load") // load
	f := func(param int) { //@ ir(f,"MakeClosure"), ir(param,"Parameter")
		if y := 1; y > 0 { //@ ir(y,"Const")
			print(v1, param) //@ ir(v1,"Load") /*load*/, ir(param,"Sigma")
		}
		param = 2      //@ ir(param,"Const")
		println(param) //@ ir(param,"Const")
	}

	f(0) //@ ir(f,"MakeClosure")

	var v2 int //@ ir(v2,"Const") // implicitly zero-initialized local value spec
	print(v2)  //@ ir(v2,"Const")

	m := make(map[string]int) //@ ir(m,"MakeMap")

	// Local value spec with multi-valued RHS:
	var v3, v4 = m[""] //@ ir(v3,"Extract"), ir(v4,"Extract"), ir(m,"MakeMap")
	print(v3)          //@ ir(v3,"Extract")
	print(v4)          //@ ir(v4,"Extract")

	v3++    //@ ir(v3,"BinOp") // assign with op
	v3 += 2 //@ ir(v3,"BinOp") // assign with op

	v5, v6 := false, "" //@ ir(v5,"Const"), ir(v6,"Const") // defining assignment
	print(v5)           //@ ir(v5,"Const")
	print(v6)           //@ ir(v6,"Const")

	var v7 S    //@ ir(v7,"&Alloc")
	v7.x = 1    //@ ir(v7,"&Alloc"), ir(x,"&FieldAddr")
	print(v7.x) //@ ir(v7,"&Alloc"), ir(x,"&FieldAddr")

	var v8 [1]int //@ ir(v8,"&Alloc")
	v8[0] = 0     //@ ir(v8,"&Alloc")
	print(v8[:])  //@ ir(v8,"&Alloc")
	_ = v8[0]     //@ ir(v8,"&Alloc")
	_ = v8[:][0]  //@ ir(v8,"&Alloc")
	v8ptr := &v8  //@ ir(v8ptr,"Alloc"), ir(v8,"&Alloc")
	_ = v8ptr[0]  //@ ir(v8ptr,"Alloc")
	_ = *v8ptr    //@ ir(v8ptr,"Alloc")

	v8a := make([]int, 1) //@ ir(v8a,"Slice")
	v8a[0] = 0            //@ ir(v8a,"Slice")
	print(v8a[:])         //@ ir(v8a,"Slice")

	v9 := S{} //@ ir(v9,"&Alloc")

	v10 := &v9 //@ ir(v10,"Alloc"), ir(v9,"&Alloc")
	_ = v10    //@ ir(v10,"Alloc")

	var v11 *J = nil //@ ir(v11,"Const")
	v11.method()     //@ ir(v11,"Const")

	var v12 J    //@ ir(v12,"&Alloc")
	v12.method() //@ ir(v12,"&Alloc") // implicitly address-taken

	// NB, in the following, 'method' resolves to the *types.Func
	// of (*J).method, so it doesn't help us locate the specific
	// ir.Values here: a bound-method closure and a promotion
	// wrapper.
	_ = v11.method            //@ ir(v11,"Const")
	_ = (*struct{ J }).method //@ ir(J,"nil")

	// These vars are not optimised away.
	if false {
		v13 := 0     //@ ir(v13,"Const")
		println(v13) //@ ir(v13,"Const")
	}

	switch x := 1; x { //@ ir(x,"Const")
	case v0: //@ ir(v0,"Phi")
	}

	for k, v := range m { //@ ir(k,"Extract"), ir(v,"Extract"), ir(m,"MakeMap")
		_ = k //@ ir(k,"Extract")
		v++   //@ ir(v,"BinOp")
	}

	if y := 0; y > 1 { //@ ir(y,"Const"), ir(y,"Const")
	}

	var i interface{}      //@ ir(i,"Const") // nil interface
	i = 1                  //@ ir(i,"MakeInterface")
	switch i := i.(type) { //@ ir(i,"MakeInterface"), ir(i,"MakeInterface")
	case int:
		println(i) //@ ir(i,"Extract")
	}

	ch := make(chan int) //@ ir(ch,"MakeChan")
	select {
	case x := <-ch: //@ ir(x,"Recv") /*receive*/, ir(ch,"MakeChan")
		_ = x //@ ir(x,"Recv")
	}

	// .Op is an inter-package FieldVal-selection.
	var err os.PathError //@ ir(err,"&Alloc")
	_ = err.Op           //@ ir(err,"&Alloc"), ir(Op,"&FieldAddr")
	_ = &err.Op          //@ ir(err,"&Alloc"), ir(Op,"&FieldAddr")

	// Exercise corner-cases of lvalues vs rvalues.
	// (Guessing IsAddr from the 'pointerness' won't cut it here.)
	type N *N
	var n N    //@ ir(n,"Const")
	n1 := n    //@ ir(n1,"Const"), ir(n,"Const")
	n2 := &n1  //@ ir(n2,"Alloc"), ir(n1,"&Alloc")
	n3 := *n2  //@ ir(n3,"Load"), ir(n2,"Alloc")
	n4 := **n3 //@ ir(n4,"Load"), ir(n3,"Load")
	_ = n4     //@ ir(n4,"Load")
}
