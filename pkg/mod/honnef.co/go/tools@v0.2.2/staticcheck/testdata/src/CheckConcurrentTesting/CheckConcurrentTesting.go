package pkg

import "testing"

func fn1() {
	var t *testing.T
	go func() { // want `the goroutine calls T\.Fatal, which must be called in the same goroutine as the test`
		t.Fatal()
	}()
	go fn2(t) // want `the goroutine calls T\.Fatal, which must be called in the same goroutine as the test`

	fn := func() {
		t.Fatal()
	}
	go fn() // want `the goroutine calls T\.Fatal, which must be called in the same goroutine as the test`
}

func fn2(t *testing.T) {
	t.Fatal()
}

func fn3(t *testing.T) {
	fn := func() {
		t.Fatal()
	}
	fn()
}

func fn4(t *testing.T) {
	t.Fatal()
}

func fn5(t *testing.T) {
	func() {
		t.Fatal()
	}()
}
