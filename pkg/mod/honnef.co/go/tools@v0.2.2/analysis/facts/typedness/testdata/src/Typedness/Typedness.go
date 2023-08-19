package pkg

import (
	"errors"
	"os/exec"
)

type T struct{ x *int }

func notAStub() {}

func fn1() *int             { return nil }
func fn2() (int, *int, int) { return 0, nil, 0 }

func fn3() (out1 int, out2 error) { notAStub(); return 0, nil }
func fn4() error                  { notAStub(); return nil }

func gen2() (out1 interface{}) { // want gen2:`always typed: 00000001`
	return 1
}

func gen3() (out1 interface{}) { // want gen3:`always typed: 00000001`
	// flag, always returns a typed value
	m := map[int]*int{}
	return m[0]
}

func gen4() (out1 int, out2 interface{}, out3 *int) { // want gen4:`always typed: 00000010`
	// flag ret[1], always a typed value
	m := map[int]*int{}
	return 0, m[0], nil
}

func gen5() (out1 interface{}) { // want gen5:`always typed: 00000001`
	// flag, propagate gen3
	return gen3()
}

func gen6(b bool) interface{} {
	// don't flag, sometimes returns untyped nil
	if b {
		m := map[int]*int{}
		return m[0]
	} else {
		return nil
	}
}

func gen7() (out1 interface{}) { // want gen7:`always typed: 00000001`
	// flag, always returns a typed value
	return fn1()
}

func gen8(x *int) (out1 interface{}) { // want gen8:`always typed: 00000001`
	// flag
	if x == nil {
		return x
	}
	return x
}

func gen9() (out1 interface{}) { // want gen9:`always typed: 00000001`
	// flag
	var x *int
	return x
}

func gen10() (out1 interface{}) { // want gen10:`always typed: 00000001`
	// flag
	var x *int
	if x == nil {
		return x
	}
	return errors.New("")
}

func gen11() interface{} {
	// don't flag, we sometimes return untyped nil
	if true {
		return nil
	} else {
		return (*int)(nil)
	}
}

func gen12(b bool) (out1 interface{}) { // want gen12:`always typed: 00000001`
	// flag, all branches return typed nils
	var x interface{}
	if b {
		x = (*int)(nil)
	} else {
		x = (*string)(nil)
	}
	return x
}

func gen13() (out1 interface{}) { // want gen13:`always typed: 00000001`
	// flag, always returns a typed value
	_, x, _ := fn2()
	return x
}

func gen14(ch chan *int) (out1 interface{}) { // want gen14:`always typed: 00000001`
	// flag
	return <-ch
}

func gen15() (out1 interface{}) { // want gen15:`always typed: 00000001`
	// flag
	t := &T{}
	return t.x
}

var g *int = new(int)

func gen16() (out1 interface{}) { // want gen16:`always typed: 00000001`
	return g
}

func gen17(x interface{}) interface{} {
	// don't flag
	if x != nil {
		return x
	}
	return x
}

func gen18() (int, error) {
	// don't flag
	_, err := fn3()
	if err != nil {
		return 0, errors.New("yo")
	}
	return 0, err
}

func gen19() (out interface{}) {
	// don't flag
	if true {
		return (*int)(nil)
	}
	return
}

func gen20() (out interface{}) {
	// don't flag
	if true {
		return (*int)(nil)
	}
	return
}

func gen21() error {
	if false {
		return (*exec.Error)(nil)
	}
	return fn4()
}

func gen22() interface{} {
	// don't flag, propagate gen6
	return gen6(false)
}

func gen23() interface{} {
	return gen24()
}

func gen24() interface{} {
	return gen23()
}

func gen25(x interface{}) (out1 interface{}) { // want gen25:`always typed: 00000001`
	return x.(interface{})
}

func gen26(x interface{}) interface{} {
	v, _ := x.(interface{})
	return v
}

func gen27(x interface{}) (out1 interface{}) {
	defer recover()
	out1 = x.(interface{})
	return out1
}

type Error struct{}

func (*Error) Error() string { return "" }

func gen28() (out1 interface{}) { // want gen28:`always typed: 00000001`
	x := new(Error)
	var y error = x
	return y
}

func gen29() (out1 interface{}) { // want gen29:`always typed: 00000001`
	var x *Error
	var y error = x
	return y
}

func gen30() (out1, out2 interface{}) { // want gen30:`always typed: 00000011`
	return gen29(), gen28()
}

func gen31() (out1 interface{}) { // want gen31:`always typed: 00000001`
	a, _ := gen30()
	return a
}

func gen32() (out1 interface{}) { // want gen32:`always typed: 00000001`
	_, b := gen30()
	return b
}

func gen33() (out1 interface{}) { // want gen33:`always typed: 00000001`
	a, b := gen30()
	_ = a
	return b
}

func gen34() (out1, out2 interface{}) { // want gen34:`always typed: 00000010`
	return nil, 1
}

func gen35() (out1 interface{}) {
	a, _ := gen34()
	return a
}

func gen36() (out1 interface{}) { // want gen36:`always typed: 00000001`
	_, b := gen34()
	return b
}
