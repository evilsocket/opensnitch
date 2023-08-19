package pkg

type M map[int]int // used

func Fn() { // used
	var n M
	_ = []M{n}
}
