package pkg

const c1 = 1 // used

const c2 = 1 // used
const c3 = 1 // used
const c4 = 1 // used
const C5 = 1 // used

const (
	c6 = 0 // used
	c7     // used
	c8     // used

	c9  // unused
	c10 // unused
	c11 // unused
)

var _ = []int{c3: 1}

type T1 struct { // used
	F1 [c1]int // used
}

func init() { // used
	_ = []int{c2: 1}
	var _ [c4]int

	_ = c7
}

func Fn() { // used
	const X = 1 // unused
}
