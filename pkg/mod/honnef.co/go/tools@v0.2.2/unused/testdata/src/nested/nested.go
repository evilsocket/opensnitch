package pkg

type t1 struct{} // unused

func (t1) fragment() {} // unused

func fn1() bool { // unused
	var v interface{} = t1{}
	switch obj := v.(type) {
	case interface {
		fragment()
	}:
		obj.fragment()
	}
	return false
}

type t2 struct{} // used

func (t2) fragment() {} // used

func Fn() bool { // used
	var v interface{} = t2{}
	switch obj := v.(type) {
	case interface {
		fragment() // used
	}:
		obj.fragment()
	}
	return false
}
