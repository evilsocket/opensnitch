package pkg

const x = 0.0

func fn() {
	_ = -0.0          // want `in Go, the floating-point literal '-0\.0' is the same as '0\.0', it does not produce a negative zero`
	_ = float32(-0.0) // want `in Go, the floating-point literal '-0\.0' is the same as '0\.0', it does not produce a negative zero`
	_ = float64(-0.0) // want `in Go, the floating-point literal '-0\.0' is the same as '0\.0', it does not produce a negative zero`
	_ = -float32(0)   // want `in Go, the floating-point expression '-float32\(0\)' is the same as 'float32\(0\)', it does not produce a negative zero`
	_ = -float64(0)   // want `in Go, the floating-point expression '-float64\(0\)' is the same as 'float64\(0\)', it does not produce a negative zero`
	_ = -float32(0.0) // want `in Go, the floating-point expression '-float32\(0\.0\)' is the same as 'float32\(0\.0\)', it does not produce a negative zero`
	_ = -float64(0.0) // want `in Go, the floating-point expression '-float64\(0\.0\)' is the same as 'float64\(0\.0\)', it does not produce a negative zero`

	// intentionally not flagged
	_ = -x
}
