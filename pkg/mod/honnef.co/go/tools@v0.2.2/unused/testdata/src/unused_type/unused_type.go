package pkg

type t1 struct{} // unused

func (t1) Fn() {} // unused

type t2 struct{} // used

func (*t2) Fn() {} // used

func init() { // used
	(*t2).Fn(nil)
}

type t3 struct{} // unused

func (t3) fn() // unused
