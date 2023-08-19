// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package typeparams

import "typeparams/lib"

type localStruct struct { F int }

func F[
	T1 ~struct{ f int },
	T2a localStruct,
	T2b lib.Struct,
	T3 ~[]int,
	T4 lib.Slice,
	T5 ~map[int]int,
	T6 lib.Map,
]() {
	_ = T1{2}
	_ = T2a{2}
	_ = T2b{2} // want "unkeyed fields"
	_ = T3{1,2}
	_ = T4{1,2}
	_ = T5{1:2}
	_ = T6{1:2}
}
