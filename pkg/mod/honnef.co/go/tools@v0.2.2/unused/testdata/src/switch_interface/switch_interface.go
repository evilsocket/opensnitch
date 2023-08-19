package pkg

type t struct{} // used

func (t) fragment() {} // used

func fn() bool { // used
	var v interface{} = t{}
	switch obj := v.(type) {
	case interface {
		fragment() // used
	}:
		obj.fragment()
	}
	return false
}

var x = fn() // used
var _ = x
