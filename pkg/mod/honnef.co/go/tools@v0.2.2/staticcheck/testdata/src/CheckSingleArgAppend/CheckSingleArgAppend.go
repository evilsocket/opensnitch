package pkg

func fn(arg []int) {
	x := append(arg) // want `x = append\(y\) is equivalent to x = y`
	_ = x
	y := append(arg, 1)
	_ = y
	arg = append(arg) // want `x = append\(y\) is equivalent to x = y`
	arg = append(arg, 1, 2, 3)
	var nilly []int
	arg = append(arg, nilly...)
	arg = append(arg, arg...)

	append := func([]int) []int { return nil }
	arg = append(arg)
}
