package pkg

import (
	"errors"
	"os/exec"
)

type T struct{ x *int }

func fn1() *int             { return nil }
func fn2() (int, *int, int) { return 0, nil, 0 }

func fn3() (int, error) { return 0, nil }
func fn4() error        { return nil }

func gen1() interface{} {
	// don't flag, returning a concrete value
	return 0
}

func gen2() interface{} {
	// don't flag, returning a concrete value
	return &T{}
}

func gen3() interface{} {
	// flag, always returns a typed value
	m := map[int]*int{}
	return m[0]
}

func gen4() (int, interface{}, *int) {
	// flag ret[1], always a typed value
	m := map[int]*int{}
	return 0, m[0], nil
}

func gen5() interface{} {
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

func gen7() interface{} {
	// flag, always returns a typed value
	return fn1()
}

func gen8(x *int) interface{} {
	// flag
	if x == nil {
		return x
	}
	return x
}

func gen9() interface{} {
	// flag
	var x *int
	return x
}

func gen10() interface{} {
	// flag
	var x *int
	if x == nil {
		return x
	}
	return errors.New("")

	// This is a tricky one. we should flag this, because it never
	// returns a nil error, but if errors.New could return untyped
	// nils, then we shouldn't flag it. we need to consider the
	// implementation of the called function.
}

func gen11() interface{} {
	// don't flag, we sometimes return untyped nil
	if true {
		return nil
	} else {
		return (*int)(nil)
	}
}

func gen12(b bool) interface{} {
	// flag, all branches return typed nils
	var x interface{}
	if b {
		x = (*int)(nil)
	} else {
		x = (*string)(nil)
	}
	return x
}

func gen13() interface{} {
	// flag, always returns a typed value
	_, x, _ := fn2()
	return x
}

func gen14(ch chan *int) interface{} {
	// flag
	return <-ch
}

func gen15() interface{} {
	// flag
	t := &T{}
	return t.x
}

var g *int = new(int)

func gen16() interface{} {
	// don't flag. returning a global is akin to returning &T{}.
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
	if true {
		return g
	}
	return (*int)(nil)
}

func test() {
	_ = gen1() == nil
	_ = gen2() == nil
	_ = gen3() == nil // want `never true`
	{
		_, r2, r3 := gen4()
		_ = r2 == nil // want `never true`
		_ = r3 == nil
	}
	_ = gen5() == nil // want `never true`
	_ = gen6(false) == nil
	_ = gen7() == nil    // want `never true`
	_ = gen8(nil) == nil // want `never true`
	_ = gen9() == nil    // want `never true`
	_ = gen10() == nil   // want `never true`
	_ = gen11() == nil
	_ = gen12(true) == nil // want `never true`
	_ = gen13() == nil     // want `never true`
	_ = gen14(nil) == nil  // want `never true`
	_ = gen15() == nil     // want `never true`
	_ = gen16() == nil
	_ = gen17(nil) == nil
	{
		_, r2 := gen18()
		_ = r2 == nil
	}
	_ = gen19() == nil
	_ = gen20() == nil
	_ = gen21() == nil
	_ = gen22() == nil // want `never true`

	var v1 interface{} = 0
	_ = v1 == nil // want `never true; the lhs`
}
