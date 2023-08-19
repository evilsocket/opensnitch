package pkg

import "strings"

func fnVariadic(s string, args ...interface{}) { // want args:"needs even elements"
	if len(args)%2 != 0 {
		panic("I'm one of those annoying logging APIs")
	}
}

func fnSlice(s string, args []interface{}) { // want args:"needs even elements"
	if len(args)%2 != 0 {
		panic("I'm one of those annoying logging APIs")
	}
}

func fnIndirect(s string, args ...interface{}) { // want args:"needs even elements"
	fnSlice(s, args)
}

func fn2(bleh []interface{}, arr1 [3]interface{}) { // want bleh:"needs even elements"
	fnVariadic("%s", 1, 2, 3) // want `variadic argument "args".+ but has 3 elements`
	args := []interface{}{1, 2, 3}
	fnVariadic("", args...)     // want `variadic argument "args".+ but has 3 elements`
	fnVariadic("", args[:1]...) // want `variadic argument "args".+ but has 1 elements`
	fnVariadic("", args[:2]...)
	fnVariadic("", args[0:1]...) // want `variadic argument "args".+ but has 1 elements`
	fnVariadic("", args[0:]...)  // want `variadic argument "args".+ but has 3 elements`
	fnVariadic("", args[:]...)   // want `variadic argument "args".+ but has 3 elements`
	fnVariadic("", bleh...)
	fnVariadic("", bleh[:1]...)  // want `variadic argument "args".+ but has 1 elements`
	fnVariadic("", bleh[0:1]...) // want `variadic argument "args".+ but has 1 elements`
	fnVariadic("", bleh[0:]...)
	fnVariadic("", bleh[:]...)
	fnVariadic("", bleh)                      // want `variadic argument "args".+ but has 1 elements`
	fnVariadic("", make([]interface{}, 3)...) // want `variadic argument "args".+ but has 3 elements`
	fnVariadic("", make([]interface{}, 4)...)
	var arr2 [3]interface{}
	fnVariadic("", arr1[:]...) // want `variadic argument "args".+ but has 3 elements`
	fnVariadic("", arr2[:]...) // want `variadic argument "args".+ but has 3 elements`

	fnSlice("", []interface{}{1, 2, 3}) // want `argument "args".+ but has 3 elements`
	fnSlice("", []interface{}{1, 2, 3, 4})

	fnIndirect("%s", 1, 2, 3) // want `argument "args".+ but has 3 elements`
	fnIndirect("%s", 1, 2)

	strings.NewReplacer("one") // want `variadic argument "oldnew".+ but has 1 elements`
	strings.NewReplacer("one", "two")
}

func fn3() {
	args := []interface{}{""}
	if true {
		fnSlice("", args) // want `but has 1 element`
	}
}
