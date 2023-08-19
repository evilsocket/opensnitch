//go:build ignore
// +build ignore

package main

// Test of maps.

var a, b, c int

func maps1() {
	m1 := map[*int]*int{&a: &b} // @line m1m1
	m2 := make(map[*int]*int)   // @line m1m2
	m2[&b] = &a

	print(m1[nil]) // @pointsto command-line-arguments.b | command-line-arguments.c
	print(m2[nil]) // @pointsto command-line-arguments.a

	print(m1) // @pointsto makemap@m1m1:21
	print(m2) // @pointsto makemap@m1m2:12

	m1[&b] = &c

	for k, v := range m1 {
		print(k) // @pointsto command-line-arguments.a | command-line-arguments.b
		print(v) // @pointsto command-line-arguments.b | command-line-arguments.c
	}

	for k, v := range m2 {
		print(k) // @pointsto command-line-arguments.b
		print(v) // @pointsto command-line-arguments.a
	}

	// Lookup doesn't create any aliases.
	print(m2[&c]) // @pointsto command-line-arguments.a
	if _, ok := m2[&a]; ok {
		print(m2[&c]) // @pointsto command-line-arguments.a
	}
}

func maps2() {
	m1 := map[*int]*int{&a: &b}
	m2 := map[*int]*int{&b: &c}
	_ = []map[*int]*int{m1, m2} // (no spurious merging of m1, m2)

	print(m1[nil]) // @pointsto command-line-arguments.b
	print(m2[nil]) // @pointsto command-line-arguments.c
}

var g int

func maps3() {
	// Regression test for a constraint generation bug for map range
	// loops in which the key is unused: the (ok, k, v) tuple
	// returned by ssa.Next may have type 'invalid' for the k and/or
	// v components, so copying the map key or value may cause
	// miswiring if the key has >1 components.  In the worst case,
	// this causes a crash.  The test below used to report that
	// pts(v) includes not just command-line-arguments.g but new(float64) too, which
	// is ill-typed.

	// sizeof(K) > 1, abstractly
	type K struct{ a, b, c, d *float64 }
	k := K{new(float64), nil, nil, nil}
	m := map[K]*int{k: &g}

	for _, v := range m {
		print(v) // @pointsto command-line-arguments.g
	}
}

var v float64

func maps4() {
	// Regression test for generating constraints for cases of key and values
	// being blank identifiers or different types assignable from the
	// corresponding map types in a range stmt.
	type K struct{ a *float64 }
	k := K{&v}
	m := map[K]*int{k: &g}

	for x, y := range m {
		print(x.a) // @pointsto command-line-arguments.v
		print(y)   // @pointsto command-line-arguments.g
	}
	var i struct{ a *float64 }
	for i, _ = range m {
		print(i.a) // @pointsto command-line-arguments.v
	}
	var j interface{}
	for _, j = range m {
		// TODO support the statement `print(j.(*int))`
		print(j) // @pointsto command-line-arguments.g
	}
	for _, _ = range m {
	}
	// do something after 'for _, _ =' to exercise the
	// effects of indexing
	for _, j = range m {
		// TODO support the statement `print(j.(*int))`
		print(j) // @pointsto command-line-arguments.g
	}
}

func main() {
	maps1()
	maps2()
	maps3()
	maps4()
}
