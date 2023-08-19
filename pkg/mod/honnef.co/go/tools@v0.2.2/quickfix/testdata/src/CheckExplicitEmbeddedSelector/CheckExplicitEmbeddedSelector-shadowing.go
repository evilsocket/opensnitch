package pkg

type Shadowing struct {
	F1 int
	BasicInner
}

func fnShadowing() {
	var shadowing Shadowing
	_ = shadowing.BasicInner.F1 // can't be simplified due to shadowing
}
