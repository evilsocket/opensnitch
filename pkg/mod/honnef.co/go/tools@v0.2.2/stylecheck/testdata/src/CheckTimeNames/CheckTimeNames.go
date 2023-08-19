// Package pkg ...
package pkg

import "time"

type T1 struct {
	aMS     int
	B       time.Duration
	BMillis time.Duration // want `don't use unit-specific suffix`
}

func fn1(a, b, cMS time.Duration) { // want `don't use unit-specific suffix`
	var x time.Duration
	var xMS time.Duration    // want `don't use unit-specific suffix`
	var y, yMS time.Duration // want `don't use unit-specific suffix`
	var zMS = time.Second    // want `don't use unit-specific suffix`
	aMS := time.Second       // want `don't use unit-specific suffix`
	unrelated, aMS := 0, 0
	aMS, bMS := 0, time.Second // want `var bMS .+ don't use unit-specific suffix`

	_, _, _, _, _, _, _, _ = x, xMS, y, yMS, zMS, aMS, unrelated, bMS
}
