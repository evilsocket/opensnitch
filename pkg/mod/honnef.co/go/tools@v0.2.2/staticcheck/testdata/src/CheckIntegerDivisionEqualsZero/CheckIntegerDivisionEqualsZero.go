package pkg

func foo(x float64) {}

func fn() {
	_ = 2 / 3 // want `results in zero`
	_ = 4 / 2
	_ = 4 / 3
	_ = 0 / 2 // want `results in zero`
	_ = 2 / 3.
	_ = 2 / 3.0
	_ = 2.0 / 3
	const _ = 2 / 3         // want `results in zero`
	const _ float64 = 2 / 3 // want `results in zero`
	_ = float64(2 / 3)      // want `results in zero`

	foo(1 / 2) // want `results in zero`
}
