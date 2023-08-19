package pkg

type MultiLevel struct{ BasicOuter }

func fnMulti() {
	var multi MultiLevel
	_ = multi.BasicOuter.BasicInner.F1 // want `could remove embedded field "BasicOuter" from selector` `could remove embedded field "BasicInner" from selector` `could simplify selectors`
	_ = multi.BasicOuter.F1            // want `could remove embedded field "BasicOuter" from selector`
	_ = multi.BasicInner.F1            // want `could remove embedded field "BasicInner" from selector`
	_ = multi.F1                       // minimal form
}
