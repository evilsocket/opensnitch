package pkg

type SomeInterface interface {
	Foo()
}

func fn(x SomeInterface) {
	_ = x.(SomeInterface)                   // want `type assertion to the same type: x already has type SomeInterface`
	y := x.(SomeInterface)                  // want `type assertion to the same type`
	y = x.(SomeInterface)                   // want `type assertion to the same type`
	var a SomeInterface = x.(SomeInterface) // want `type assertion to the same type`
	z, _ := x.(SomeInterface)               // want `type assertion to the same type`
	z, _ = x.(SomeInterface)                // want `type assertion to the same type`

	_, ok := x.(SomeInterface) // want `type assertion to the same type`
	_, ok = x.(SomeInterface)  // want `type assertion to the same type`
	_, _ = x.(SomeInterface)   // want `type assertion to the same type`

	if z, ok := x.(SomeInterface); ok { // want `type assertion to the same type`
		_ = z
	}
	if _, ok := x.(SomeInterface); !ok { // want `type assertion to the same type`
	}
	if _, ok = x.(SomeInterface); !ok { // want `type assertion to the same type`
	}
	if z, ok = x.(SomeInterface); ok { // want `type assertion to the same type`
	}
	if z := x.(SomeInterface); true { // want `type assertion to the same type`
		_ = z
	}
	if z, _ := x.(SomeInterface); true { // want `type assertion to the same type`
		_ = z
	}
	if _, _ = x.(SomeInterface); true { // want `type assertion to the same type`
	}
	if _ = x.(SomeInterface); true { // want `type assertion to the same type`
	}

	switch x.(type) {
	case SomeInterface:
	}

	_ = a
	_ = y
	_ = ok
	_ = z
}
