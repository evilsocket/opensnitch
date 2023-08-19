package main

import (
	_ "fmt"
)

func (smith *Smith) initStatements() {
	smith.statements = []func(){
		smith.stmtOas,
		smith.stmtAs,
		smith.stmtInc,
		smith.stmtIf,
		smith.stmtFor,
		smith.stmtSend,
		smith.stmtRecv,
		smith.stmtSelect,
		smith.stmtSwitchExpr,
		smith.stmtSwitchType,
		smith.stmtTypeDecl,
		smith.stmtVarDecl,
		smith.stmtCall,
		smith.stmtReturn,
		smith.stmtBreak,
		smith.stmtContinue,
		smith.stmtGoto,
		smith.stmtSink,
	}
}

func (smith *Smith) genStatement() {
	if smith.stmtCount >= NStatements {
		return
	}
	smith.exprCount = 0
	smith.stmtCount++
	smith.statements[smith.rnd(len(smith.statements))]()
}

func (smith *Smith) stmtOas() {
	list := smith.atypeList(TraitAny)
	str, vars := smith.fmtOasVarList(list)
	smith.line("%v := %v", str, smith.fmtRvalueList(list))
	for _, v := range vars {
		smith.defineVar(v.id, v.typ)
	}
}

func (smith *Smith) stmtReturn() {
	smith.line("return %v", smith.fmtRvalueList(smith.curFunc.rets))
}

func (smith *Smith) stmtAs() {
	types := smith.atypeList(TraitAny)
	smith.line("%v = %v", smith.fmtLvalueList(types), smith.fmtRvalueList(types))
}

func (smith *Smith) stmtInc() {
	smith.line("%v %v", smith.lvalueOrMapIndex(smith.atype(ClassNumeric)), smith.choice("--", "++"))
}

func (smith *Smith) stmtIf() {
	smith.enterBlock(true)
	smith.enterBlock(true)
	if smith.rndBool() {
		smith.line("if %v {", smith.rvalue(smith.atype(ClassBoolean)))
	} else {
		smith.line("if %v; %v {", smith.stmtSimple(true, nil), smith.rvalue(smith.atype(ClassBoolean)))
	}
	smith.genBlock()
	if smith.rndBool() {
		smith.line("} else {")
		smith.genBlock()
	}
	smith.leaveBlock()
	smith.line("}")
	smith.leaveBlock()
}

func (smith *Smith) stmtFor() {
	smith.enterBlock(true)
	smith.enterBlock(true)
	smith.curBlock.isBreakable = true
	smith.curBlock.isContinuable = true
	var vars []*Var
	switch smith.choice("simple", "complex", "range") {
	case "simple":
		smith.line("for %v {", smith.rvalue(smith.atype(ClassBoolean)))
	case "complex":
		smith.line("for %v; %v; %v {", smith.stmtSimple(true, nil), smith.rvalue(smith.atype(ClassBoolean)), smith.stmtSimple(false, nil))
	case "range":
		switch smith.choice("slice", "string", "channel", "map") {
		case "slice":
			t := smith.atype(TraitAny)
			s := smith.rvalue(smith.sliceOf(t))
			switch smith.choice("one", "two", "oneDecl", "twoDecl") {
			case "one":
				smith.line("for %v = range %v {", smith.lvalueOrBlank(smith.intType), s)
			case "two":
				smith.line("for %v, %v = range %v {", smith.lvalueOrBlank(smith.intType), smith.lvalueOrBlank(t), s)
			case "oneDecl":
				id := smith.newId("Var")
				smith.line("for %v := range %v {", id, s)
				vars = append(vars, &Var{id: id, typ: smith.intType})
			case "twoDecl":
				types := []*Type{smith.intType, t}
				str := ""
				str, vars = smith.fmtOasVarList(types)
				smith.line("for %v := range %v {", str, s)
			default:
				panic("bad")
			}
		case "string":
			s := smith.rvalue(smith.stringType)
			switch smith.choice("one", "two", "oneDecl", "twoDecl") {
			case "one":
				smith.line("for %v = range %v {", smith.lvalueOrBlank(smith.intType), s)
			case "two":
				smith.line("for %v, %v = range %v {", smith.lvalueOrBlank(smith.intType), smith.lvalueOrBlank(smith.runeType), s)
			case "oneDecl":
				id := smith.newId("Var")
				smith.line("for %v := range %v {", id, s)
				vars = append(vars, &Var{id: id, typ: smith.intType})
			case "twoDecl":
				types := []*Type{smith.intType, smith.runeType}
				str := ""
				str, vars = smith.fmtOasVarList(types)
				smith.line("for %v := range %v {", str, s)
			default:
				panic("bad")
			}
		case "channel":
			cht := smith.atype(ClassChan)
			ch := smith.rvalue(cht)
			switch smith.choice("one", "oneDecl") {
			case "one":
				smith.line("for %v = range %v {", smith.lvalueOrBlank(cht.ktyp), ch)
			case "oneDecl":
				id := smith.newId("Var")
				smith.line("for %v := range %v {", id, ch)
				vars = append(vars, &Var{id: id, typ: cht.ktyp})
			default:
				panic("bad")
			}
		case "map":
			t := smith.atype(ClassMap)
			m := smith.rvalue(t)
			switch smith.choice("one", "two", "oneDecl", "twoDecl") {
			case "one":
				smith.line("for %v = range %v {", smith.lvalueOrBlank(t.ktyp), m)
			case "two":
				smith.line("for %v, %v = range %v {", smith.lvalueOrBlank(t.ktyp), smith.lvalueOrBlank(t.vtyp), m)
			case "oneDecl":
				id := smith.newId("Var")
				smith.line("for %v := range %v {", id, m)
				vars = append(vars, &Var{id: id, typ: t.ktyp})
			case "twoDecl":
				types := []*Type{t.ktyp, t.vtyp}
				str := ""
				str, vars = smith.fmtOasVarList(types)
				smith.line("for %v := range %v {", str, m)
			default:
				panic("bad")
			}
		default:
			panic("bad")
		}
	default:
		panic("bad")
	}
	smith.enterBlock(true)
	if len(vars) > 0 {
		smith.line("")
		for _, v := range vars {
			smith.defineVar(v.id, v.typ)
		}
	}
	smith.genBlock()
	smith.leaveBlock()
	smith.leaveBlock()
	smith.line("}")
	smith.leaveBlock()
}

func (smith *Smith) stmtSimple(oas bool, newVars *[]*Var) string {
	// We emit a fake statement in "oas", so make sure that nothing can be inserted in between.
	if smith.curBlock.extendable {
		panic("bad")
	}
	// "send" crashes gccgo with random errors too frequently.
	// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=61273
	switch smith.choice("empty", "inc", "assign", "oas", "send", "expr") {
	case "empty":
		return ""
	case "inc":
		return F("%v %v", smith.lvalueOrMapIndex(smith.atype(ClassNumeric)), smith.choice("--", "++"))
	case "assign":
		list := smith.atypeList(TraitAny)
		return F("%v = %v", smith.fmtLvalueList(list), smith.fmtRvalueList(list))
	case "oas":
		if !oas {
			return ""
		}
		list := smith.atypeList(TraitAny)
		str, vars := smith.fmtOasVarList(list)
		if newVars != nil {
			*newVars = vars
		}
		res := F("%v := %v", str, smith.fmtRvalueList(list))
		smith.line("")
		for _, v := range vars {
			smith.defineVar(v.id, v.typ)
		}
		return res
	case "send":
		t := smith.atype(TraitSendable)
		return F("%v <- %v", smith.rvalue(t), smith.rvalue(t.ktyp))
	case "expr":
		return ""
	default:
		panic("bad")
	}
}

func (smith *Smith) stmtSend() {
	t := smith.atype(TraitSendable)
	smith.line("%v <- %v", smith.rvalue(t), smith.rvalue(t.ktyp))
}

func (smith *Smith) stmtRecv() {
	t := smith.atype(TraitReceivable)
	ch := smith.rvalue(t)
	switch smith.choice("normal", "decl") {
	case "normal":
		smith.line("%v, %v = <-%v", smith.lvalueOrBlank(t.ktyp), smith.lvalueOrBlank(smith.boolType), ch)
	case "decl":
		vv := smith.newId("Var")
		ok := smith.newId("Var")
		smith.line("%v, %v := <-%v", vv, ok, ch)
		smith.defineVar(vv, t.ktyp)
		smith.defineVar(ok, smith.boolType)
	default:
		panic("bad")
	}
}

func (smith *Smith) stmtTypeDecl() {
	id := smith.newId("Type")
	t := smith.atype(TraitAny)
	smith.line("type %v %v", id, t.id)

	newTyp := new(Type)
	*newTyp = *t
	newTyp.id = id
	newTyp.namedUserType = true
	if t.class == ClassStruct {
		newTyp.literal = func() string {
			// replace struct name with new type id
			l := t.literal()
			l = l[len(t.id)+1:]
			return "(" + id + l
		}
		newTyp.complexLiteral = func() string {
			// replace struct name with new type id
			l := t.complexLiteral()
			l = l[len(t.id)+1:]
			return "(" + id + l
		}
	} else {
		newTyp.literal = func() string {
			return F("%v(%v)", id, t.literal())
		}
		if t.complexLiteral != nil {
			newTyp.complexLiteral = func() string {
				return F("%v(%v)", id, t.complexLiteral())
			}
		}
	}
	smith.defineType(newTyp)
}

func (smith *Smith) stmtVarDecl() {
	id := smith.newId("Var")
	t := smith.atype(TraitAny)
	smith.line("var %v %v = %v", id, t.id, smith.rvalue(t))
	smith.defineVar(id, t)
}

func (smith *Smith) stmtSelect() {
	smith.enterBlock(true)
	smith.line("select {")
	for smith.rnd(5) != 0 {
		smith.enterBlock(true)
		elem := smith.atype(TraitAny)
		cht := smith.chanOf(elem)
		ch := smith.rvalue(cht)
		if smith.rndBool() {
			smith.line("case %v <- %v:", ch, smith.rvalue(elem))
		} else {
			switch smith.choice("one", "two", "oneDecl", "twoDecl") {
			case "one":
				smith.line("case %v = <-%v:", smith.lvalueOrBlank(elem), ch)
			case "two":
				smith.line("case %v, %v = <-%v:", smith.lvalueOrBlank(elem), smith.lvalueOrBlank(smith.boolType), ch)
			case "oneDecl":
				vv := smith.newId("Var")
				smith.line("case %v := <-%v:", vv, ch)
				smith.defineVar(vv, elem)
			case "twoDecl":
				vv := smith.newId("Var")
				ok := smith.newId("Var")
				smith.line("case %v, %v := <-%v:", vv, ok, ch)
				smith.defineVar(vv, elem)
				smith.defineVar(ok, smith.boolType)
			default:
				panic("bad")
			}
		}
		smith.genBlock()
		smith.leaveBlock()
	}
	if smith.rndBool() {
		smith.enterBlock(true)
		smith.line("default:")
		smith.genBlock()
		smith.leaveBlock()
	}
	smith.line("}")
	smith.leaveBlock()
}

func (smith *Smith) stmtSwitchExpr() {
	var t *Type
	cond := ""
	if smith.rndBool() {
		t = smith.atype(TraitComparable)
		cond = smith.rvalue(t)
	} else {
		t = smith.boolType
	}
	smith.enterBlock(true)
	smith.enterBlock(true)
	smith.curBlock.isBreakable = true
	var vars []*Var
	if smith.rndBool() {
		smith.line("switch %v {", cond)
	} else {
		smith.line("switch %v; %v {", smith.stmtSimple(true, &vars), cond)
	}
	// TODO: we generate at most one case, because if we generate more,
	// we can generate two cases with equal constants.
	fallthru := false
	if smith.rndBool() {
		smith.enterBlock(true)
		smith.line("case %v:", smith.rvalue(t))
		smith.genBlock()
		smith.leaveBlock()
		if smith.rndBool() {
			fallthru = true
			smith.line("fallthrough")
		}
	}
	if fallthru || len(vars) > 0 || smith.rndBool() {
		smith.enterBlock(true)
		smith.line("default:")
		smith.genBlock()
		for _, v := range vars {
			smith.line("_ = %v", v.id)
			v.used = true
		}
		smith.leaveBlock()
	}
	smith.leaveBlock()
	smith.line("}")
	smith.leaveBlock()
}

func (smith *Smith) stmtSwitchType() {
	cond := smith.lvalue(smith.atype(TraitAny))
	smith.enterBlock(true)
	smith.curBlock.isBreakable = true
	smith.line("switch COND := (interface{})(%v); COND.(type) {", cond)
	if smith.rndBool() {
		smith.enterBlock(true)
		smith.line("case %v:", smith.atype(TraitAny).id)
		smith.genBlock()
		smith.leaveBlock()
	}
	if smith.rndBool() {
		smith.enterBlock(true)
		smith.line("default:")
		smith.genBlock()
		smith.leaveBlock()
	}
	smith.line("}")
	smith.leaveBlock()
}

func (smith *Smith) stmtCall() {
	if smith.rndBool() {
		smith.stmtCallBuiltin()
	}
	t := smith.atype(ClassFunction)
	prefix := smith.choice("", "go", "defer")
	smith.line("%v %v(%v)", prefix, smith.rvalue(t), smith.fmtRvalueList(t.styp))
}

func (smith *Smith) stmtCallBuiltin() {
	prefix := smith.choice("", "go", "defer")
	switch fn := smith.choice("close", "copy", "delete", "panic", "print", "println", "recover"); fn {
	case "close":
		smith.line("%v %v(%v)", prefix, fn, smith.rvalue(smith.atype(ClassChan)))
	case "copy":
		smith.line("%v %v", prefix, smith.exprCopySlice())
	case "delete":
		t := smith.atype(ClassMap)
		smith.line("%v %v(%v, %v)", prefix, fn, smith.rvalue(t), smith.rvalue(t.ktyp))
	case "panic":
		smith.line("%v %v(%v)", prefix, fn, smith.rvalue(smith.atype(TraitAny)))
	case "print":
		fallthrough
	case "println":
		list := smith.atypeList(TraitPrintable)
		smith.line("%v %v(%v)", prefix, fn, smith.fmtRvalueList(list))
	case "recover":
		smith.line("%v %v()", prefix, fn)
	default:
		panic("bad")
	}
}

func (smith *Smith) stmtBreak() {
	if !smith.curBlock.isBreakable {
		return
	}
	smith.line("break")
}

func (smith *Smith) stmtContinue() {
	if !smith.curBlock.isContinuable {
		return
	}
	smith.line("continue")
}

func (smith *Smith) stmtGoto() {
	// TODO: support goto down
	id := smith.materializeGotoLabel()
	smith.line("goto %v", id)
}

func (smith *Smith) stmtSink() {
	// Makes var escape.
	smith.line("SINK = %v", smith.exprVar(smith.atype(TraitAny)))
}
