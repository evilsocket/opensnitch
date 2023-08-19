package pkg

import "fmt"

func fn() {
	_ = fmt.Sprint("foo")  // want `unnecessary use of fmt\.Sprint`
	_ = fmt.Sprintf("foo") // want `unnecessary use of fmt\.Sprintf`
	_ = fmt.Sprintf("foo %d")
	_ = fmt.Sprintf("foo %d", 1)

	var x string
	_ = fmt.Sprint(x)
}
