package pkg

func fnDepth() {
	type T4 struct{ F int }
	type T5 struct{ T4 }
	type T3 struct{ T5 }
	type T2 struct{ T4 }

	type T1 struct {
		T2
		T3
	}

	var v T1
	_ = v.F
	_ = v.T2.F // want `could remove embedded field "T2" from selector`
	_ = v.T3.F
}
