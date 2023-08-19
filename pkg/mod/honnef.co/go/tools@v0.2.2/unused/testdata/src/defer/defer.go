package pkg

type t struct{} // used

func (t) fn1() {} // used
func (t) fn2() {} // used
func fn1()     {} // used
func fn2()     {} // used

func Fn() { // used
	var v t
	defer fn1()
	defer v.fn1()
	go fn2()
	go v.fn2()
}
