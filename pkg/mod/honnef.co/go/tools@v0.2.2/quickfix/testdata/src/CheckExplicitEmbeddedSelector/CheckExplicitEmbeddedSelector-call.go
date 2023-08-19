package pkg

type FunctionCallOuter struct{ FunctionCallInner }
type FunctionCallInner struct {
	F8 func() FunctionCallContinuedOuter
}
type FunctionCallContinuedOuter struct{ FunctionCallContinuedInner }
type FunctionCallContinuedInner struct{ F9 int }

func fnCall() {
	var call FunctionCallOuter
	_ = call.FunctionCallInner.F8().FunctionCallContinuedInner.F9 // want `could remove embedded field "FunctionCallInner" from selector` `could remove embedded field "FunctionCallContinuedInner" from selector` `could simplify selectors`
	_ = call.F8().F9                                              // minimal form
}
