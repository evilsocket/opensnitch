package pkg

const iota = 0

const (
	a = iota
)

func fn(x int) {
	_ = x | a
}
