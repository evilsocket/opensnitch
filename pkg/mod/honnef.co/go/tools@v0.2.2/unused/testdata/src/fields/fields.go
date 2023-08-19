// Test of field usage detection

package pkg

type t1 struct { // used
	f11 int // used
	f12 int // used
}
type t2 struct { // used
	f21 int // used
	f22 int // used
}
type t3 struct { // used
	f31 t4 // used
}
type t4 struct { // used
	f41 int // used
}
type t5 struct { // used
	f51 int // used
}
type t6 struct { // used
	f61 int // used
}
type t7 struct { // used
	f71 int // used
}
type m1 map[string]t7 // used
type t8 struct {      // used
	f81 int // used
}
type t9 struct { // used
	f91 int // used
}
type t10 struct { // used
	f101 int // used
}
type t11 struct { // used
	f111 int // used
}
type s1 []t11     // used
type t12 struct { // used
	f121 int // used
}
type s2 []t12     // used
type t13 struct { // used
	f131 int // used
}
type t14 struct { // used
	f141 int // used
}
type a1 [1]t14    // used
type t15 struct { // used
	f151 int // used
}
type a2 [1]t15    // used
type t16 struct { // used
	f161 int // used
}
type t17 struct { // unused
	f171 int
	f172 int
}
type t18 struct { // used
	f181 int // used
	f182 int // unused
	f183 int // unused
}

type t19 struct { // used
	f191 int // used
}
type m2 map[string]t19 // used

type t20 struct { // used
	f201 int // used
}
type m3 map[string]t20 // used

type t21 struct { // used
	f211 int // unused
	f212 int // used
}
type t22 struct { // unused
	f221 int
	f222 int
}

func foo() { // used
	_ = t10{1}
	_ = t21{f212: 1}
	_ = []t1{{1, 2}}
	_ = t2{1, 2}
	_ = []struct {
		a int // used
	}{{1}}

	// XXX
	// _ = []struct{ foo struct{ bar int } }{{struct{ bar int }{1}}}

	_ = []t1{t1{1, 2}}
	_ = []t3{{t4{1}}}
	_ = map[string]t5{"a": {1}}
	_ = map[t6]string{{1}: "a"}
	_ = m1{"a": {1}}
	_ = map[t8]t8{{}: {1}}
	_ = map[t9]t9{{1}: {}}
	_ = s1{{1}}
	_ = s2{2: {1}}
	_ = [...]t13{{1}}
	_ = a1{{1}}
	_ = a2{0: {1}}
	_ = map[[1]t16]int{{{1}}: 1}
	y := struct {
		x int // used
	}{}
	_ = y
	_ = t18{f181: 1}
	_ = []m2{{"a": {1}}}
	_ = [][]m3{{{"a": {1}}}}
}

func init() { foo() } // used

func superUnused() { // unused
	var _ struct {
		x int
	}
}
