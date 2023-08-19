package pkg

func foo(a, b int) int { return a + b } // want foo:"is pure"
func bar(a, b int) int {
	println(a + b)
	return a + b
}

func empty()            {}
func stubPointer() *int { return nil }
func stubInt() int      { return 0 }

func fn3() {
	empty()
	stubPointer()
	stubInt()
}

func ptr1() *int { return new(int) }
func ptr2() *int { var x int; return &x }
func lit() []int { return []int{} }

var X int

func load() int        { _ = X; return 0 }
func assign(x int) int { _ = x; return 0 } // want assign:"is pure"
