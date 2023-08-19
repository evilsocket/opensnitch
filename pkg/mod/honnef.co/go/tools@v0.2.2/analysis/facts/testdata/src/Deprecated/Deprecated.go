package pkg

// Deprecated: Don't use this.
func fn2() { // want fn2:`Deprecated: Don't use this\.`
}

// This is a function.
//
// Deprecated: Don't use this.
//
// Here is how you might use it instead.
func fn3() { // want fn3:`Deprecated: Don't use this\.`
}
