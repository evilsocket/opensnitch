package main

import (
	"bufio"
	"bytes"
	"fmt"
)

type TypeClass int

const (
	ClassBoolean TypeClass = iota
	ClassNumeric
	ClassComplex
	ClassString
	ClassArray
	ClassSlice
	ClassStruct
	ClassPointer
	ClassFunction
	ClassInterface
	ClassMap
	ClassChan

	TraitAny
	TraitOrdered
	TraitComparable
	TraitIndexable
	TraitReceivable
	TraitSendable
	TraitHashable
	TraitPrintable
	TraitLenCapable
	TraitGlobal
)

type Type struct {
	id             string
	class          TypeClass
	namedUserType  bool
	ktyp           *Type   // map key, chan elem, array elem, slice elem, pointee type
	vtyp           *Type   // map val
	utyp           *Type   // underlying type
	styp           []*Type // function arguments
	rtyp           []*Type // function return values
	elems          []*Var  // struct fields and interface methods
	literal        func() string
	complexLiteral func() string

	// TODO: cache types
	// pointerTo *Type
}

func (smith *Smith) initTypes() {
	smith.predefinedTypes = []*Type{
		{id: "string", class: ClassString, literal: func() string { return "\"foo\"" }},
		{id: "bool", class: ClassBoolean, literal: func() string { return "false" }},
		{id: "int", class: ClassNumeric, literal: func() string { return "1" }},
		{id: "byte", class: ClassNumeric, literal: func() string { return "byte(0)" }},
		{id: "interface{}", class: ClassInterface, literal: func() string { return "interface{}(nil)" }},
		{id: "rune", class: ClassNumeric, literal: func() string { return "rune(0)" }},
		{id: "float32", class: ClassNumeric, literal: func() string { return "float32(1.0)" }},
		{id: "float64", class: ClassNumeric, literal: func() string { return "1.0" }},
		{id: "complex64", class: ClassComplex, literal: func() string { return "complex64(1i)" }},
		{id: "complex128", class: ClassComplex, literal: func() string { return "1i" }},

		{id: "uint", class: ClassNumeric, literal: func() string { return "uint(1)" }},
		{id: "uintptr", class: ClassNumeric, literal: func() string { return "uintptr(0)" }},
		{id: "int16", class: ClassNumeric, literal: func() string { return "int16(1)" }},
		{id: "error", class: ClassInterface, literal: func() string { return "error(nil)" }},
	}
	for _, t := range smith.predefinedTypes {
		t.utyp = t
	}

	smith.stringType = smith.predefinedTypes[0]
	smith.boolType = smith.predefinedTypes[1]
	smith.intType = smith.predefinedTypes[2]
	smith.byteType = smith.predefinedTypes[3]
	smith.efaceType = smith.predefinedTypes[4]
	smith.runeType = smith.predefinedTypes[5]
	smith.float32Type = smith.predefinedTypes[6]
	smith.float64Type = smith.predefinedTypes[7]
	smith.complex64Type = smith.predefinedTypes[8]
	smith.complex128Type = smith.predefinedTypes[9]

	smith.stringType.complexLiteral = func() string {
		if smith.rndBool() {
			return `"ab\x0acd"`
		}
		return "`abc\\x0acd`"
	}
}

func fmtTypeList(list []*Type, parens bool) string {
	var buf bytes.Buffer
	if parens || len(list) > 1 {
		buf.Write([]byte{'('})
	}
	for i, t := range list {
		if i != 0 {
			buf.Write([]byte{','})
		}
		fmt.Fprintf(&buf, "%v", t.id)
	}
	if parens || len(list) > 1 {
		buf.Write([]byte{')'})
	}
	return buf.String()
}

func (smith *Smith) atype(trait TypeClass) *Type {
	smith.typeDepth++
	defer func() {
		smith.typeDepth--
	}()
	for {
		if smith.typeDepth >= 3 || smith.rndBool() {
			var cand []*Type
			for _, t := range smith.types() {
				if smith.satisfiesTrait(t, trait) {
					cand = append(cand, t)
				}
			}
			if len(cand) > 0 {
				return cand[smith.rnd(len(cand))]
			}
		}
		t := smith.typeLit()
		if t != nil && smith.satisfiesTrait(t, trait) {
			return t
		}
	}
}

func (smith *Smith) typeLit() *Type {
	switch smith.choice("array", "chan", "struct", "pointer", "interface", "slice", "function", "map") {
	case "array":
		return smith.arrayOf(smith.atype(TraitAny))
	case "chan":
		return smith.chanOf(smith.atype(TraitAny))
	case "struct":
		var elems []*Var
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "struct { ")
		for smith.rndBool() {
			e := &Var{id: smith.newId("Field"), typ: smith.atype(TraitAny)}
			elems = append(elems, e)
			fmt.Fprintf(&buf, "%v %v\n", e.id, e.typ.id)
		}
		fmt.Fprintf(&buf, "}")
		id := buf.String()
		return &Type{
			id:    id,
			class: ClassStruct,
			elems: elems,
			literal: func() string {
				return F("(%v{})", id)
			},
			complexLiteral: func() string {
				if smith.rndBool() {
					// unnamed
					var buf bytes.Buffer
					fmt.Fprintf(&buf, "(%v{", id)
					for i := 0; i < len(elems); i++ {
						fmt.Fprintf(&buf, "%v, ", smith.rvalue(elems[i].typ))
					}
					fmt.Fprintf(&buf, "})")
					return buf.String()
				} else {
					// named
					var buf bytes.Buffer
					fmt.Fprintf(&buf, "(%v{", id)
					for i := 0; i < len(elems); i++ {
						if smith.rndBool() {
							fmt.Fprintf(&buf, "%v: %v, ", elems[i].id, smith.rvalue(elems[i].typ))
						}
					}
					fmt.Fprintf(&buf, "})")
					return buf.String()
				}
			},
		}
	case "pointer":
		return pointerTo(smith.atype(TraitAny))
	case "interface":
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "interface { ")
		for smith.rndBool() {
			fmt.Fprintf(&buf, " %v %v %v\n", smith.newId("Method"),
				fmtTypeList(smith.atypeList(TraitAny), true),
				fmtTypeList(smith.atypeList(TraitAny), false))
		}
		fmt.Fprintf(&buf, "}")
		return &Type{
			id:    buf.String(),
			class: ClassInterface,
			literal: func() string {
				return F("%v(nil)", buf.String())
			},
		}
	case "slice":
		return smith.sliceOf(smith.atype(TraitAny))
	case "function":
		return smith.funcOf(smith.atypeList(TraitAny), smith.atypeList(TraitAny))
	case "map":
		ktyp := smith.atype(TraitHashable)
		vtyp := smith.atype(TraitAny)
		return &Type{
			id:    F("map[%v]%v", ktyp.id, vtyp.id),
			class: ClassMap,
			ktyp:  ktyp,
			vtyp:  vtyp,
			literal: func() string {
				if smith.rndBool() {
					cap := ""
					if smith.rndBool() {
						cap = "," + smith.rvalue(smith.intType)
					}
					return F("make(map[%v]%v %v)", ktyp.id, vtyp.id, cap)
				} else {
					return F("map[%v]%v{}", ktyp.id, vtyp.id)
				}
			},
		}
	default:
		panic("bad")
	}
}

func (smith *Smith) satisfiesTrait(t *Type, trait TypeClass) bool {
	if trait < TraitAny {
		return t.class == trait
	}

	switch trait {
	case TraitAny:
		return true
	case TraitOrdered:
		return t.class == ClassNumeric || t.class == ClassString
	case TraitComparable:
		return t.class == ClassBoolean || t.class == ClassNumeric || t.class == ClassString ||
			t.class == ClassPointer || t.class == ClassChan || t.class == ClassInterface
	case TraitIndexable:
		return t.class == ClassArray || t.class == ClassSlice || t.class == ClassString ||
			t.class == ClassMap
	case TraitReceivable:
		return t.class == ClassChan
	case TraitSendable:
		return t.class == ClassChan
	case TraitHashable:
		if t.class == ClassFunction || t.class == ClassMap || t.class == ClassSlice {
			return false
		}
		if t.class == ClassArray && !smith.satisfiesTrait(t.ktyp, TraitHashable) {
			return false
		}
		if t.class == ClassStruct {
			for _, e := range t.elems {
				if !smith.satisfiesTrait(e.typ, TraitHashable) {
					return false
				}
			}
		}
		return true
	case TraitPrintable:
		return t.class == ClassBoolean || t.class == ClassNumeric || t.class == ClassString ||
			t.class == ClassPointer || t.class == ClassInterface
	case TraitLenCapable:
		return t.class == ClassString || t.class == ClassSlice || t.class == ClassArray ||
			t.class == ClassMap || t.class == ClassChan
	case TraitGlobal:
		for _, t1 := range smith.predefinedTypes {
			if t == t1 {
				return true
			}
		}
		return false
	default:
		panic("bad")
	}
}

func (smith *Smith) atypeList(trait TypeClass) []*Type {
	n := smith.rnd(4) + 1
	list := make([]*Type, n)
	for i := 0; i < n; i++ {
		list[i] = smith.atype(trait)
	}
	return list
}

func typeList(t *Type, n int) []*Type {
	list := make([]*Type, n)
	for i := 0; i < n; i++ {
		list[i] = t
	}
	return list
}

func pointerTo(elem *Type) *Type {
	return &Type{
		id:    F("*%v", elem.id),
		class: ClassPointer,
		ktyp:  elem,
		literal: func() string {
			return F("(*%v)(nil)", elem.id)
		}}
}

func (smith *Smith) chanOf(elem *Type) *Type {
	return &Type{
		id:    F("chan %v", elem.id),
		class: ClassChan,
		ktyp:  elem,
		literal: func() string {
			cap := ""
			if smith.rndBool() {
				cap = "," + smith.rvalue(smith.intType)
			}
			return F("make(chan %v %v)", elem.id, cap)
		},
	}
}

func (smith *Smith) sliceOf(elem *Type) *Type {
	return &Type{
		id:    F("[]%v", elem.id),
		class: ClassSlice,
		ktyp:  elem,
		literal: func() string {
			return F("[]%v{}", elem.id)
		},
		complexLiteral: func() string {
			switch smith.choice("normal", "keyed") {
			case "normal":
				return F("[]%v{%v}", elem.id, smith.fmtRvalueList(typeList(elem, smith.rnd(3))))
			case "keyed":
				n := smith.rnd(3)
				var indexes []int
			loop:
				for len(indexes) < n {
					i := smith.rnd(10)
					for _, i1 := range indexes {
						if i1 == i {
							continue loop
						}
					}
					indexes = append(indexes, i)
				}
				var buf bytes.Buffer
				fmt.Fprintf(&buf, "[]%v{", elem.id)
				for i, idx := range indexes {
					if i != 0 {
						fmt.Fprintf(&buf, ",")
					}
					fmt.Fprintf(&buf, "%v: %v", idx, smith.rvalue(elem))
				}
				fmt.Fprintf(&buf, "}")
				return buf.String()
			default:
				panic("bad")
			}
		},
	}
}

func (smith *Smith) arrayOf(elem *Type) *Type {
	size := smith.rnd(3)
	return &Type{
		id:    F("[%v]%v", size, elem.id),
		class: ClassArray,
		ktyp:  elem,
		literal: func() string {
			return F("[%v]%v{}", size, elem.id)
		},
		complexLiteral: func() string {
			switch smith.choice("normal", "keyed") {
			case "normal":
				return F("[%v]%v{%v}", smith.choice(F("%v", size), "..."), elem.id, smith.fmtRvalueList(typeList(elem, size)))
			case "keyed":
				var buf bytes.Buffer
				fmt.Fprintf(&buf, "[%v]%v{", size, elem.id)
				for i := 0; i < size; i++ {
					if i != 0 {
						fmt.Fprintf(&buf, ",")
					}
					fmt.Fprintf(&buf, "%v: %v", i, smith.rvalue(elem))
				}
				fmt.Fprintf(&buf, "}")
				return buf.String()
			default:
				panic("bad")
			}
		},
	}
}

func (smith *Smith) funcOf(alist, rlist []*Type) *Type {
	t := &Type{
		id:    F("func%v %v", fmtTypeList(alist, true), fmtTypeList(rlist, false)),
		class: ClassFunction,
		styp:  alist,
		rtyp:  rlist,
	}
	t.literal = func() string {
		return F("((func%v %v)(nil))", fmtTypeList(alist, true), fmtTypeList(rlist, false))
	}
	t.complexLiteral = func() string {
		return smith.genFuncLit(t)
	}
	return t
}

func (smith *Smith) genFuncLit(ft *Type) string {
	//return F("((func%v %v)(nil))", fmtTypeList(ft.styp, true), fmtTypeList(ft.rtyp, false))

	if smith.curBlockPos == -1 {
		smith.line("")
	}

	f := &Func{args: ft.styp, rets: ft.rtyp}
	curFunc0 := smith.curFunc
	smith.curFunc = f
	curBlock0 := smith.curBlock
	curBlockPos0 := smith.curBlockPos
	curBlockLen0 := len(smith.curBlock.sub)
	exprDepth0 := smith.exprDepth
	exprCount0 := smith.exprCount
	smith.exprDepth = 0
	smith.exprCount = 0
	defer func() {
		smith.curBlock = curBlock0
		smith.curFunc = curFunc0
		smith.exprDepth = exprDepth0
		smith.exprCount = exprCount0
		smith.curBlockPos = curBlockPos0 + (len(smith.curBlock.sub) - curBlockLen0)
	}()

	fb := &Block{parent: smith.curBlock, subBlock: smith.curBlock.sub[smith.curBlockPos]}
	smith.curBlock = fb
	smith.enterBlock(true)
	smith.enterBlock(true)
	argIds := make([]string, len(f.args))
	argStr := ""
	for i, a := range f.args {
		argIds[i] = smith.newId("Param")
		if i != 0 {
			argStr += ", "
		}
		argStr += argIds[i] + " " + a.id
	}
	smith.line("func(%v)%v {", argStr, fmtTypeList(f.rets, false))
	for i, a := range f.args {
		smith.defineVar(argIds[i], a)
	}
	smith.curBlock.funcBoundary = true
	smith.genBlock()
	smith.leaveBlock()
	smith.stmtReturn()
	smith.line("}")
	smith.leaveBlock()

	//b := curBlock.sub[curBlockPos]
	//copy(curBlock.sub[curBlockPos:], curBlock.sub[curBlockPos+1:])
	//curBlock.sub = curBlock.sub[:len(curBlock.sub)-1]

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	serializeBlock(w, fb, 0)
	w.Flush()
	s := buf.String()
	//fmt.Printf("GEN FUNC:\n%v\n", s)
	return s[:len(s)-1]
}

func dependsOn(t, t0 *Type) bool {
	if t == nil {
		return false
	}
	if t.class == ClassInterface {
		// We don't know how to walk all types referenced by an interface yet.
		return true
	}
	if t0 == nil && t.namedUserType {
		return true
	}
	if t == t0 {
		return true
	}
	if dependsOn(t.ktyp, t0) {
		return true
	}
	if dependsOn(t.vtyp, t0) {
		return true
	}
	if dependsOn(t.ktyp, t0) {
		return true
	}
	for _, t1 := range t.styp {
		if dependsOn(t1, t0) {
			return true
		}
	}
	for _, t1 := range t.rtyp {
		if dependsOn(t1, t0) {
			return true
		}
	}
	for _, e := range t.elems {
		if dependsOn(e.typ, t0) {
			return true
		}
	}
	return false
}
