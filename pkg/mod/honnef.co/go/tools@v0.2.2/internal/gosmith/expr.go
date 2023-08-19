package main

import (
	"bytes"
	"fmt"
)

func (smith *Smith) initExpressions() {
	smith.expressions = []func(res *Type) string{
		smith.exprLiteral,
		smith.exprVar,
		smith.exprFunc,
		smith.exprSelectorField,
		smith.exprRecv,
		smith.exprArith,
		smith.exprEqual,
		smith.exprOrder,
		smith.exprCall,
		smith.exprCallBuiltin,
		smith.exprAddress,
		smith.exprDeref,
		smith.exprSlice,
		smith.exprIndexSlice,
		smith.exprIndexArray,
		smith.exprIndexString,
		smith.exprIndexMap,
		smith.exprConversion,
	}
}

func (smith *Smith) expression(res *Type) string {
	smith.exprCount++
	smith.totalExprCount++
	if smith.exprDepth >= NExprDepth || smith.exprCount >= NExprCount || smith.totalExprCount >= NTotalExprCount {
		return res.literal()
	}
	for {
		smith.exprDepth++
		s := smith.expressions[smith.rnd(len(smith.expressions))](res)
		smith.exprDepth--
		if s != "" {
			return s
		}
	}
}

func (smith *Smith) rvalue(t *Type) string {
	return smith.expression(t)
}

// rvalue, but not a const
// used to index arrays and strings
func (smith *Smith) nonconstRvalue(t *Type) string {
	if t.class != ClassNumeric {
		panic("bad")
	}
trying:
	for {
		res := ""
		switch smith.choice("lvalue", "call", "len", "selector", "recv", "arith", "indexMap", "conv") {
		case "lvalue":
			res = smith.lvalue(t)
		case "call":
			res = smith.exprCall(t)
		case "len":
			tt := smith.atype(TraitLenCapable)
			fn := smith.choice("len", "cap")
			if (tt.class == ClassString || tt.class == ClassMap) && fn == "cap" {
				break
			}
			if tt.class == ClassArray {
				// len/cap are const
				break
			}
			res = F("(%v)((%v)(%v))", t.id, fn, smith.lvalue(tt))
		case "selector":
			res = smith.exprSelectorField(t)
		case "recv":
			res = smith.exprRecv(t)
		case "arith":
			res = F("(%v) %v (%v)", smith.lvalue(t), smith.choice("+", "-"), smith.rvalue(t))
		case "indexMap":
			res = smith.exprIndexMap(t)
		case "conv":
			res = F("(%v)(%v %v)", t.id, smith.lvalue(smith.atype(ClassNumeric)), smith.choice("", ","))
		default:
			panic("bad")
		}
		if res == "" {
			continue trying
		}
		return res
	}
}

func (smith *Smith) lvalue(t *Type) string {
	for {
		switch smith.choice("var", "indexSlice", "indexArray", "selector", "deref") {
		case "var":
			return smith.exprVar(t)
		case "indexSlice":
			return smith.exprIndexSlice(t)
		case "indexArray":
			return F("(%v)[%v]", smith.lvalue(smith.arrayOf(t)), smith.nonconstRvalue(smith.intType))
		case "selector":
			for i := 0; i < 10; i++ {
				st := smith.atype(ClassStruct)
				for _, e := range st.elems {
					if e.typ == t {
						return F("(%v).%v", smith.lvalue(st), e.id)
					}
				}
			}
			continue
		case "deref":
			return smith.exprDeref(t)
		default:
			panic("bad")
		}
	}
}

func (smith *Smith) lvalueOrBlank(t *Type) string {
	for {
		switch smith.choice("lvalue", "map", "blank") {
		case "lvalue":
			return smith.lvalue(t)
		case "map":
			if e := smith.exprIndexMap(t); e != "" {
				return e
			}
		case "blank":
			return "_"
		default:
			panic("bad")
		}
	}
}

func (smith *Smith) lvalueOrMapIndex(t *Type) string {
	for {
		switch smith.choice("lvalue", "map") {
		case "lvalue":
			return smith.lvalue(t)
		case "map":
			if e := smith.exprIndexMap(t); e != "" {
				return e
			}
		default:
			panic("bad")
		}
	}
}

func (smith *Smith) fmtRvalueList(list []*Type) string {
	var buf bytes.Buffer
	for i, t := range list {
		if i != 0 {
			buf.Write([]byte{','})
		}
		fmt.Fprintf(&buf, "%v", smith.rvalue(t))
	}
	return buf.String()
}

func (smith *Smith) fmtLvalueList(list []*Type) string {
	var buf bytes.Buffer
	for i, t := range list {
		if i != 0 {
			buf.Write([]byte{','})
		}
		buf.WriteString(smith.lvalueOrBlank(t))
	}
	return buf.String()
}

func (smith *Smith) fmtOasVarList(list []*Type) (str string, newVars []*Var) {
	allVars := smith.vars()
	var buf bytes.Buffer
	for i, t := range list {
		expr := "_"
		// First, try to find an existing var in the same scope.
		if smith.rndBool() {
			for i, v := range allVars {
				if v.typ == t && v.block == smith.curBlock {
					allVars[i] = allVars[len(allVars)-1]
					allVars = allVars[:len(allVars)-1]
					expr = v.id
					break
				}
			}
		}
		if smith.rndBool() || (i == len(list)-1 && len(newVars) == 0) {
			expr = smith.newId("Var")
			newVars = append(newVars, &Var{id: expr, typ: t})
		}

		if i != 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(expr)
	}
	return buf.String(), newVars
}

func (smith *Smith) exprLiteral(res *Type) string {
	if res.complexLiteral != nil {
		return res.complexLiteral()
	}
	return res.literal()
}

func (smith *Smith) exprVar(res *Type) string {
	for _, v := range smith.vars() {
		if v.typ == res {
			return v.id
		}
	}
	return smith.materializeVar(res)
}

func (smith *Smith) exprSelectorField(res *Type) string {
	for i := 0; i < 10; i++ {
		st := smith.atype(ClassStruct)
		for _, e := range st.elems {
			if e.typ == res {
				return F("(%v).%v", smith.rvalue(st), e.id)
			}
		}
	}
	return ""
}

func (smith *Smith) exprFunc(res *Type) string {
	if !smith.satisfiesTrait(res, TraitGlobal) {
		return ""
	}
	var f *Func
	for _, f1 := range smith.packages[smith.curPackage].toplevFuncs {
		if len(f1.rets) == 1 && f1.rets[0] == res {
			f = f1
			break
		}
	}
	if f == nil {
		f = smith.materializeFunc([]*Type{res})
	}
	if smith.rndBool() {
		return F("%v(%v)", f.name, smith.fmtRvalueList(f.args))
	} else {
		var f0 *Func
	loop:
		for _, f1 := range smith.packages[smith.curPackage].toplevFuncs {
			if len(f1.rets) == len(f.args) {
				for i := range f.args {
					// TODO: check assignability
					if f1.rets[i] != f.args[i] {
						continue loop
					}
				}
				f0 = f1
				break
			}
		}
		if f0 == nil {
			f0 = smith.materializeFunc(f.args)
		}
		return F("%v(%v(%v))", f.name, f0.name, smith.fmtRvalueList(f0.args))
	}
}

func (smith *Smith) exprAddress(res *Type) string {
	if res.class != ClassPointer {
		return ""
	}
	if res.ktyp.class == ClassStruct && smith.rndBool() {
		return F("&%v", res.ktyp.complexLiteral())
	}
	return F("(%v)(&(%v))", res.id, smith.lvalue(res.ktyp))
}

func (smith *Smith) exprDeref(res *Type) string {
	return F("(*(%v))", smith.lvalue(pointerTo(res)))
}

func (smith *Smith) exprRecv(res *Type) string {
	t := smith.chanOf(res)
	return F("(<- %v)", smith.rvalue(t))
}

func (smith *Smith) exprArith(res *Type) string {
	if res.class != ClassNumeric && res.class != ClassComplex {
		return ""
	}
	// "/" causes division by zero
	// "*" causes generation of -1 index in int(real(1i * 1i))
	return F("(%v) + (%v)", smith.rvalue(res), smith.rvalue(res))
}

func (smith *Smith) exprEqual(res *Type) string {
	if res != smith.boolType {
		return ""
	}
	t := smith.atype(TraitComparable)
	return F("(%v) %v (%v)", smith.rvalue(t), smith.choice("==", "!="), smith.rvalue(t))
}

func (smith *Smith) exprOrder(res *Type) string {
	if res != smith.boolType {
		return ""
	}
	t := smith.atype(TraitOrdered)
	return F("(%v) %v (%v)", smith.rvalue(t), smith.choice("<", "<=", ">", ">="), smith.rvalue(t))

}

func (smith *Smith) exprCall(ret *Type) string {
	t := smith.funcOf(smith.atypeList(TraitAny), []*Type{ret})
	return F("%v(%v)", smith.rvalue(t), smith.fmtRvalueList(t.styp))
}

func (smith *Smith) exprCallBuiltin(ret *Type) string {
	switch fn := smith.choice("append", "cap", "complex", "copy", "imag", "len", "make", "new", "real", "recover"); fn {
	case "append":
		if ret.class != ClassSlice {
			return ""
		}
		switch smith.choice("one", "two", "slice") {
		case "one":
			return F("%v(%v, %v)", fn, smith.rvalue(ret), smith.rvalue(ret.ktyp))
		case "two":
			return F("%v(%v, %v, %v)", fn, smith.rvalue(ret), smith.rvalue(ret.ktyp), smith.rvalue(ret.ktyp))
		case "slice":
			return F("%v(%v, %v...)", fn, smith.rvalue(ret), smith.rvalue(ret))
		default:
			panic("bad")
		}
	case "len", "cap":
		if ret != smith.intType { // TODO: must be convertable
			return ""
		}
		t := smith.atype(TraitLenCapable)
		if (t.class == ClassString || t.class == ClassMap) && fn == "cap" {
			return ""

		}
		return F("%v(%v)", fn, smith.rvalue(t))
	case "copy":
		if ret != smith.intType {
			return ""
		}
		return F("%v", smith.exprCopySlice())
	case "make":
		if ret.class != ClassSlice && ret.class != ClassMap && ret.class != ClassChan {
			return ""
		}
		cap := ""
		if ret.class == ClassSlice {
			if smith.rndBool() {
				cap = F(", %v", smith.rvalue(smith.intType))
			} else {
				// Careful to not generate "len larger than cap".
				cap = F(", 0, %v", smith.rvalue(smith.intType))
			}
		} else if smith.rndBool() {
			cap = F(", %v", smith.rvalue(smith.intType))
		}
		return F("make(%v %v)", ret.id, cap)
	case "new":
		if ret.class != ClassPointer {
			return ""
		}
		return F("new(%v)", ret.ktyp.id)
	case "recover":
		if ret != smith.efaceType {
			return ""
		}
		return "recover()"
	case "real", "imag":
		if ret == smith.float32Type {
			return F("real(%v)", smith.rvalue(smith.complex64Type))
		}
		if ret == smith.float64Type {
			return F("real(%v)", smith.rvalue(smith.complex128Type))
		}
		return ""
	case "complex":
		if ret == smith.complex64Type {
			return F("complex(%v, %v)", smith.rvalue(smith.float32Type), smith.rvalue(smith.float32Type))
		}
		if ret == smith.complex128Type {
			return F("complex(%v, %v)", smith.rvalue(smith.float64Type), smith.rvalue(smith.float64Type))
		}
		return ""
	default:
		panic("bad")
	}
}

func (smith *Smith) exprCopySlice() string {
	if smith.rndBool() {
		t := smith.atype(ClassSlice)
		return F("copy(%v, %v)", smith.rvalue(t), smith.rvalue(t))
	} else {
		return F("copy(%v, %v)", smith.rvalue(smith.sliceOf(smith.byteType)), smith.rvalue(smith.stringType))
	}
}

func (smith *Smith) exprSlice(ret *Type) string {
	if ret.class != ClassSlice {
		return ""
	}
	i0 := ""
	if smith.rndBool() {
		i0 = smith.nonconstRvalue(smith.intType)
	}
	i2 := ""
	if smith.rndBool() {
		i2 = ":" + smith.nonconstRvalue(smith.intType)
	}
	i1 := ":"
	if smith.rndBool() || i2 != "" {
		i1 = ":" + smith.nonconstRvalue(smith.intType)
	}
	return F("(%v)[%v%v%v]", smith.rvalue(ret), i0, i1, i2)
}

func (smith *Smith) exprIndexSlice(ret *Type) string {
	return F("(%v)[%v]", smith.rvalue(smith.sliceOf(ret)), smith.nonconstRvalue(smith.intType))
}

func (smith *Smith) exprIndexString(ret *Type) string {
	if ret != smith.byteType {
		return ""
	}
	return F("(%v)[%v]", smith.rvalue(smith.stringType), smith.nonconstRvalue(smith.intType))
}

func (smith *Smith) exprIndexArray(ret *Type) string {
	// TODO: also handle indexing of pointers to arrays
	return F("(%v)[%v]", smith.rvalue(smith.arrayOf(ret)), smith.nonconstRvalue(smith.intType))
}

func (smith *Smith) exprIndexMap(ret *Type) string {
	// TODO: figure out something better
	for i := 0; i < 10; i++ {
		t := smith.atype(ClassMap)
		if t.vtyp == ret {
			return F("(%v)[%v]", smith.rvalue(t), smith.rvalue(t.ktyp))
		}
	}
	return ""
}

func (smith *Smith) exprConversion(ret *Type) string {
	if ret.class == ClassNumeric {
		return F("(%v)(%v %v)", ret.id, smith.rvalue(smith.atype(ClassNumeric)), smith.choice("", ","))
	}
	if ret.class == ClassComplex {
		return F("(%v)(%v %v)", ret.id, smith.rvalue(smith.atype(ClassComplex)), smith.choice("", ","))
	}
	if ret == smith.stringType {
		switch smith.choice("int", "byteSlice", "runeSlice") {
		case "int":
			// We produce a string of length at least 3, to not produce
			// "invalid string index 1 (out of bounds for 1-byte string)"
			return F("(%v)((%v) + (1<<24) %v)", ret.id, smith.rvalue(smith.intType), smith.choice("", ","))
		case "byteSlice":
			return F("(%v)(%v %v)", ret.id, smith.rvalue(smith.sliceOf(smith.byteType)), smith.choice("", ","))
		case "runeSlice":
			return F("(%v)(%v %v)", ret.id, smith.rvalue(smith.sliceOf(smith.runeType)), smith.choice("", ","))
		default:
			panic("bad")
		}
	}
	if ret.class == ClassSlice && (ret.ktyp == smith.byteType || ret.ktyp == smith.runeType) {
		return F("(%v)(%v %v)", ret.id, smith.rvalue(smith.stringType), smith.choice("", ","))
	}
	// TODO: handle "x is assignable to T"
	// TODO: handle "x's type and T have identical underlying types"
	// TODO: handle "x's type and T are unnamed pointer types and their pointer base types have identical underlying types"
	return ""
}
