package pkg

import "sort"

type T1 []int
type T2 T1
type T3 [1]int
type T4 string

func fn(arg1 interface{}, arg2 []int) {
	var v1 T1
	var v2 T2
	var v3 T3
	var v4 T4
	var v5 []int
	var v6 interface{} = []int{}
	var v7 interface{}
	if true {
		v7 = []int{}
	} else {
		v7 = 0
	}
	var v8 interface{} = 0
	sort.Slice(arg1, nil)
	sort.Slice(arg2, nil)
	sort.Slice(v1, nil)
	sort.Slice(v2, nil)
	sort.Slice(v3, nil) // want `sort\.Slice must only be called on slices, was called on \[1\]int`
	sort.Slice(v4, nil) // want `sort\.Slice must only be called on slices, was called on string`
	sort.Slice(v5, nil)
	sort.Slice(v6, nil)
	sort.Slice(v7, nil)
	sort.Slice(v8, nil) // want `sort\.Slice must only be called on slices, was called on int`
	sort.Slice([]int{}, nil)
	sort.Slice(0, nil)         // want `sort\.Slice must only be called on slices, was called on int`
	sort.Slice(nil, nil)       // want `cannot call sort\.Slice on nil literal`
	sort.SliceIsSorted(0, nil) // want `sort\.SliceIsSorted must only be called on slices, was called on int`
	sort.SliceStable(0, nil)   // want `sort\.SliceStable must only be called on slices, was called on int`
}
