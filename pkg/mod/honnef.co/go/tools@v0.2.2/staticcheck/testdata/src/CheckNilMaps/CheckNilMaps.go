package pkg

import "fmt"

func fn1() {
	var m map[int]int
	m[1] = 1 // want `assignment to nil map`
}

func fn2(m map[int]int) {
	m[1] = 1
}

func fn3() {
	v := []int{1, 2, 3}
	var m map[string]int
	for i := range v {
		m["a"] = i // want `assignment to nil map`
	}
	fmt.Println(m["a"])
}

func fn4() {
	m := map[string]int{}
	if true {
		if true {
			m[""] = 0
		}
	}
}
