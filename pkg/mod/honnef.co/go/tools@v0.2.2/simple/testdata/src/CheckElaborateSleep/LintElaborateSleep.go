package pkg

import (
	"fmt"
	"time"
)

func fn() {
	time.Sleep(0)

	select { // want `should use time.Sleep`
	case <-time.After(0):
	}

	select { // want `should use time.Sleep`
	case <-time.After(0):
		fmt.Println("yay")
	}

	const d = 0
	select { // want `should use time.Sleep`
	case <-time.After(d):
	}

	var ch chan int
	select {
	case <-time.After(0):
	case <-ch:
	}
}
