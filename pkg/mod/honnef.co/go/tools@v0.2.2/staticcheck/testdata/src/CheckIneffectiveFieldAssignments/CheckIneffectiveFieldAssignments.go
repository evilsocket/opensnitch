package pkg

type T1 struct {
	T2 // make sure embedded fields don't throw off our numbering
	x  int
	y  int
	z  T2
}

type T2 struct {
	x int
	y int
	z int
}

type T3 struct {
	T2
}

func (v T1) fn1() {
	v.x = 1
	v.y = 1 // want `ineffective assignment to field T1.y`
	println(v.x)
}

func (v T1) fn2() {
	println(v.x)
	v.x = 1 // want `ineffective assignment to field T1.x`
}

func (v T1) fn3() {
	if true {
		println(v.x)
	}
	v.x = 1 // want `ineffective assignment to field T1.x`
}

func (v T1) fn10() {
	v.x = 1
	if true {
		println(v.x)
	}
}

func (v T1) fn4() {
	v.x = 1
	v.dump()
}

func (v T1) fn5() {
	v.dump()
	v.x = 1 // want `ineffective assignment to field T1.x`
}

func (v T1) fn6() {
	v.x = 1
	v.y = 1
	println(v.y)
	println(v.x)
}

func (v T1) fn7() {
	// not currently being flagged because it's a nested field
	v.z.x = 1
}

func (v T1) fn8() {
	v.x++ // want `ineffective assignment to field T1.x`
}

func (v T1) fn9() {
	v.x++
	println(v.x)
}

func (v T1) fn11() {
	v = T1{x: 42, y: 23} // not currently being flagged
}

func (v T1) fn12() {
	v = T1{x: 42, y: 23} // not currently being flagged
	println(v.y)
}

func (v T1) fn13() {
	v = T1{x: 42}
	v.y = 23 // not currently being flagged, we gave up when we saw the assignment to v
	println(v.x)
}

func (v T1) fn14() {
	v = T1{x: 42} // not currently being flagged
	v.y = 23
	println(v.y)
}

func (v T1) fn15() {
	// not currently being flagged
	v = T1{x: 42}
}

func (v T1) dump() {}

func (v T3) fn1() {
	// not currently being flagged because it's a nested field (via
	// embedding)
	v.x = 1
}
