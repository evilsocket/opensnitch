package pkg

import _ "syscall"

func fn() {
	// not flagged because we're importing syscall
	var x int = 1
	_ = x
}
