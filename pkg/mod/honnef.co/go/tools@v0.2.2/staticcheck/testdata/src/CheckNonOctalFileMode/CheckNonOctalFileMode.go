package pkg

import "os"

func fn() {
	os.OpenFile("", 0, 644) // want `file mode.+`
}

func fn2() (string, int, os.FileMode) {
	return "", 0, 0
}

func fn3() {
	os.OpenFile(fn2())
}
