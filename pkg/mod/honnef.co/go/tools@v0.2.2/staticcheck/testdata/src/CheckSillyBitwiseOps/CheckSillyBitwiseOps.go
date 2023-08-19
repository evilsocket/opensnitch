package pkg

const a = 0

const (
	b = iota
	c
)

const (
	y = 42

	d = iota
)

func fn(x int) {
	println(x | 0)        // want `x \| 0 always equals x`
	println(x & 0)        // want `x & 0 always equals 0`
	println(x ^ 0)        // want `x \^ 0 always equals x`
	println((x << 5) | 0) // want `\(x << 5\) \| 0 always equals \(x << 5\)`
	println(x | 1)
	println(x << 0)

	println(x | a)
	println(x | b) // want `x \| b always equals x; b is defined as iota`
	println(x & b) // want `x & b always equals 0; b is defined as iota`
	println(x | c)

	// d is iota, but its value is 1
	println(x | d)
}
