package pkg

import "fmt"

// T is t
type T struct {
	X bool
	F string
}

// Modify modifies T.F to say modified, then calls EchoF.
func (t T) Modify() {
	if t.X {
		t.X, t.F = true, "modified"
	}
	t.EchoF()
}

// EchoF prints F.
func (t T) EchoF() {
	fmt.Println(t.F)
}

func main() {
	t := T{X: true, F: "original"}

	t.EchoF()  // output: original
	t.Modify() // output: modified
	t.EchoF()  // output: original
}
