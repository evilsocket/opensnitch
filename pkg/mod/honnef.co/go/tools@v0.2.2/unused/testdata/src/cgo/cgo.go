package pkg

//go:cgo_export_dynamic
func foo() {} // used

func bar() {} // unused
