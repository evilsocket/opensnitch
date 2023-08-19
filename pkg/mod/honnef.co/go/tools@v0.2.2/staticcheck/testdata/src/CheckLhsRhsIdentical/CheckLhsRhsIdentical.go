package pkg

import "math/rand"

type Float float64

type Floats [5]float64
type Ints [5]int

type T1 struct {
	A float64
	B float64
}

type T2 struct {
	A float64
	B int
}

func fn(a int, s []int, f1 float64, f2 Float, fs Floats, is Ints, t1 T1, t2 T2) {
	if 0 == 0 { // want `identical expressions`
		println()
	}
	if 1 == 1 { // want `identical expressions`
		println()
	}
	if a == a { // want `identical expressions`
		println()
	}
	if a != a { // want `identical expressions`
		println()
	}
	if s[0] == s[0] { // want `identical expressions`
		println()
	}
	if 1&1 == 1 { // want `identical expressions`
		println()
	}
	if (1 + 2 + 3) == (1 + 2 + 3) { // want `identical expressions`
		println()
	}
	if f1 == f1 {
		println()
	}
	if f1 != f1 {
		println()
	}
	if f1 > f1 {
		println()
	}
	if f1-f1 == 0 {
		println()
	}
	if f2 == f2 {
		println()
	}
	if fs == fs {
		println()
	}
	if is == is { // want `identical expressions`
		println()
	}
	if t1 == t1 {
		println()
	}
	if t2 == t2 { // want `identical expressions`
		println()
	}
}

func fn2() {
	_ = rand.Int() - rand.Int()
	_ = rand.Int31() - rand.Int31()
	_ = rand.Int31n(0) - rand.Int31n(0)
	_ = rand.Int63() - rand.Int63()
	_ = rand.Int63n(0) - rand.Int63n(0)
	_ = rand.Intn(0) - rand.Intn(0)
	_ = rand.Uint32() - rand.Uint32()
	_ = rand.Uint64() - rand.Uint64()
	_ = rand.ExpFloat64() - rand.ExpFloat64()
	_ = rand.Float32() - rand.Float32()
	_ = rand.Float64() - rand.Float64()
	_ = rand.NormFloat64() - rand.NormFloat64()

	var rng *rand.Rand
	_ = rng.Int() - rng.Int()
	_ = rng.Int31() - rng.Int31()
	_ = rng.Int31n(0) - rng.Int31n(0)
	_ = rng.Int63() - rng.Int63()
	_ = rng.Int63n(0) - rng.Int63n(0)
	_ = rng.Intn(0) - rng.Intn(0)
	_ = rng.Uint32() - rng.Uint32()
	_ = rng.Uint64() - rng.Uint64()
	_ = rng.ExpFloat64() - rng.ExpFloat64()
	_ = rng.Float32() - rng.Float32()
	_ = rng.Float64() - rng.Float64()
	_ = rng.NormFloat64() - rng.NormFloat64()

	_ = rand.NewSource(0) == rand.NewSource(0) // want `identical expressions`
}
