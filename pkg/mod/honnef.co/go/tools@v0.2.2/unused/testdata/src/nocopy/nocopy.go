package bar

type myNoCopy1 struct{}  // used
type myNoCopy2 struct{}  // used
type locker struct{}     // unused
type someStruct struct { // unused
	x int
}

func (myNoCopy1) Lock()      {} // used
func (recv myNoCopy2) Lock() {} // used
func (locker) Lock()         {} // unused
func (locker) Unlock()       {} // unused
func (someStruct) Lock()     {} // unused

type T struct { // used
	noCopy1 myNoCopy1  // used
	noCopy2 myNoCopy2  // used
	field1  someStruct // unused
	field2  locker     // unused
	field3  int        // unused
}
