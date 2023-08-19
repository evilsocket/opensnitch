package main

/*
Large uncovered parts are:
- methods
- type assignability and identity
- consts
- interfaces, types implementing interfaces, type assertions
- ... parameters
*/

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

type Smith struct {
	curPackage  int
	curBlock    *Block
	curBlockPos int
	curFunc     *Func

	packages [NPackages]*Package

	idSeq          int
	typeDepth      int
	stmtCount      int
	exprDepth      int
	exprCount      int
	totalExprCount int

	predefinedTypes []*Type
	stringType      *Type
	boolType        *Type
	intType         *Type
	byteType        *Type
	efaceType       *Type
	runeType        *Type
	float32Type     *Type
	float64Type     *Type
	complex64Type   *Type
	complex128Type  *Type

	statements  []func()
	expressions []func(res *Type) string

	rng *rand.Rand
}

const (
	NPackages = 3
	NFiles    = 3

	NStatements     = 10
	NExprDepth      = 4
	NExprCount      = 10
	NTotalExprCount = 50

/*
	NStatements     = 30
	NExprDepth      = 6
	NExprCount      = 20
	NTotalExprCount = 1000
*/
)

type Package struct {
	name    string
	imports map[string]bool
	top     *Block

	undefFuncs []*Func
	undefVars  []*Var

	toplevVars  []*Var
	toplevFuncs []*Func
}

type Block struct {
	str           string
	parent        *Block
	subBlock      *Block
	extendable    bool
	isBreakable   bool
	isContinuable bool
	funcBoundary  bool
	sub           []*Block
	consts        []*Const
	types         []*Type
	funcs         []*Func
	vars          []*Var
}

type Func struct {
	name string
	args []*Type
	rets []*Type
}

type Var struct {
	id    string
	typ   *Type
	block *Block
	used  bool
}

type Const struct {
}

func (smith *Smith) writeProgram(dir string) {
	smith.initTypes()
	smith.initExpressions()
	smith.initStatements()
	smith.initProgram()
	for pi := range smith.packages {
		smith.genPackage(pi)
	}
	smith.serializeProgram(dir)
}

func (smith *Smith) initProgram() {
	smith.packages[0] = smith.newPackage("main")
	smith.packages[0].undefFuncs = []*Func{
		{name: "init", args: []*Type{}, rets: []*Type{}},
		{name: "init", args: []*Type{}, rets: []*Type{}},
		{name: "main", args: []*Type{}, rets: []*Type{}},
	}
	if !*singlepkg {
		smith.packages[1] = smith.newPackage("a")
		smith.packages[2] = smith.newPackage("b")
	}
}

func (smith *Smith) newPackage(name string) *Package {
	return &Package{name: name, imports: make(map[string]bool), top: &Block{extendable: true}}
}

func (smith *Smith) genPackage(pi int) {
	smith.typeDepth = 0
	smith.stmtCount = 0
	smith.exprDepth = 0
	smith.exprCount = 0
	smith.totalExprCount = 0

	p := smith.packages[pi]
	if p == nil {
		return
	}
	for len(p.undefFuncs) != 0 || len(p.undefVars) != 0 {
		if len(p.undefFuncs) != 0 {
			f := p.undefFuncs[len(p.undefFuncs)-1]
			p.undefFuncs = p.undefFuncs[:len(p.undefFuncs)-1]
			smith.genToplevFunction(pi, f)
		}
		if len(p.undefVars) != 0 {
			v := p.undefVars[len(p.undefVars)-1]
			p.undefVars = p.undefVars[:len(p.undefVars)-1]
			smith.genToplevVar(pi, v)
		}
	}
}

func F(f string, args ...interface{}) string {
	return fmt.Sprintf(f, args...)
}

func (smith *Smith) line(f string, args ...interface{}) {
	s := F(f, args...)
	b := &Block{parent: smith.curBlock, str: s}
	if smith.curBlockPos+1 == len(smith.curBlock.sub) {
		smith.curBlock.sub = append(smith.curBlock.sub, b)
	} else {
		smith.curBlock.sub = append(smith.curBlock.sub, nil)
		copy(smith.curBlock.sub[smith.curBlockPos+2:], smith.curBlock.sub[smith.curBlockPos+1:])
		smith.curBlock.sub[smith.curBlockPos+1] = b
	}
	smith.curBlockPos++
}

func (smith *Smith) resetContext(pi int) {
	smith.curPackage = pi
	p := smith.packages[pi]
	smith.curBlock = p.top
	smith.curBlockPos = len(smith.curBlock.sub) - 1
	smith.curFunc = nil
}

func (smith *Smith) genToplevFunction(pi int, f *Func) {
	smith.resetContext(pi)
	smith.curFunc = f
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
	smith.line("func %v(%v)%v {", f.name, argStr, fmtTypeList(f.rets, false))
	for i, a := range f.args {
		smith.defineVar(argIds[i], a)
	}
	smith.curBlock.funcBoundary = true
	smith.genBlock()
	smith.leaveBlock()
	smith.stmtReturn()
	smith.line("}")
	smith.leaveBlock()
	if f.name != "init" {
		smith.packages[smith.curPackage].toplevFuncs = append(smith.packages[smith.curPackage].toplevFuncs, f)
	}
}

func (smith *Smith) genToplevVar(pi int, v *Var) {
	smith.resetContext(pi)
	smith.enterBlock(true)
	smith.line("var %v = %v", v.id, smith.rvalue(v.typ))
	smith.leaveBlock()
	smith.packages[smith.curPackage].toplevVars = append(smith.packages[smith.curPackage].toplevVars, v)
}

func (smith *Smith) genBlock() {
	smith.enterBlock(false)
	for smith.rnd(10) != 0 {
		smith.genStatement()
	}
	smith.leaveBlock()
}

func (smith *Smith) serializeProgram(dir string) {
	for _, p := range smith.packages {
		if p == nil {
			continue
		}
		path := filepath.Join(dir, "src", p.name)
		os.MkdirAll(path, os.ModePerm)
		nf := NFiles
		if *singlefile {
			nf = 1
		}
		files := make([]*bufio.Writer, nf)
		for i := range files {
			fname := filepath.Join(path, fmt.Sprintf("%v.go", i))
			f, err := os.Create(fname)
			if err != nil {
				fmt.Fprintf(os.Stdout, "failed to create a file: %v\n", err)
				os.Exit(1)
			}
			w := bufio.NewWriter(bufio.NewWriter(f))
			files[i] = w
			defer func() {
				w.Flush()
				f.Close()
			}()
			fmt.Fprintf(w, "package %s\n", p.name)
			for imp := range p.imports {
				fmt.Fprintf(w, "import \"%s\"\n", imp)
			}
			if i == 0 && p.name == "main" {
				fmt.Fprintf(w, "import \"runtime\"\n")
				fmt.Fprintf(w, "func init() {\n")
				fmt.Fprintf(w, "	go func() {\n")
				fmt.Fprintf(w, "		for {\n")
				fmt.Fprintf(w, "			runtime.GC()\n")
				fmt.Fprintf(w, "			runtime.Gosched()\n")
				fmt.Fprintf(w, "		}\n")
				fmt.Fprintf(w, "	}()\n")
				fmt.Fprintf(w, "}\n")
			}
			for imp := range p.imports {
				fmt.Fprintf(w, "var _ = %s.UsePackage\n", imp)
			}
			if i == 0 {
				fmt.Fprintf(w, "var UsePackage = 0\n")
				fmt.Fprintf(w, "var SINK interface{}\n")
			}
		}
		for _, decl := range p.top.sub {
			serializeBlock(files[smith.rnd(len(files))], decl, 0)
		}
	}

	path := filepath.Join(dir, "src", "a")
	os.MkdirAll(path, os.ModePerm)
	fname := filepath.Join(path, "0_test.go")
	f, err := os.Create(fname)
	if err != nil {
		fmt.Fprintf(os.Stdout, "failed to create a file: %v\n", err)
		os.Exit(1)
	}
	f.Write([]byte("package a\n"))
	f.Close()
}

func serializeBlock(w *bufio.Writer, b *Block, d int) {
	if true {
		if b.str != "" {
			w.WriteString(b.str)
			w.WriteString("\n")
		}
	} else {
		w.WriteString("/*" + strings.Repeat("*", d) + "*/ ")
		w.WriteString(b.str)
		w.WriteString(F(" // ext=%v vars=%v types=%v", b.extendable, len(b.vars), len(b.types)))
		w.WriteString("\n")
	}
	for _, b1 := range b.sub {
		serializeBlock(w, b1, d+1)
	}
}

func (smith *Smith) vars() []*Var {
	var vars []*Var
	vars = append(vars, smith.packages[smith.curPackage].toplevVars...)
	var f func(b *Block, pos int)
	f = func(b *Block, pos int) {
		for _, b1 := range b.sub[:pos+1] {
			vars = append(vars, b1.vars...)
		}
		if b.parent != nil {
			pos := len(b.parent.sub) - 1
			if b.subBlock != nil {
				pos = -2
				for i, b1 := range b.parent.sub {
					if b1 == b.subBlock {
						pos = i
						break
					}
				}
				if pos == -2 {
					panic("bad")
				}
			}
			f(b.parent, pos)
		}
	}
	f(smith.curBlock, smith.curBlockPos)
	return vars
}

func (smith *Smith) types() []*Type {
	var types []*Type
	types = append(types, smith.predefinedTypes...)
	var f func(b *Block, pos int)
	f = func(b *Block, pos int) {
		for _, b1 := range b.sub[:pos+1] {
			types = append(types, b1.types...)
		}
		if b.parent != nil {
			pos := len(b.parent.sub) - 1
			if b.subBlock != nil {
				pos = -2
				for i, b1 := range b.parent.sub {
					if b1 == b.subBlock {
						pos = i
						break
					}
				}
				if pos == -2 {
					panic("bad")
				}
			}
			f(b.parent, pos)
		}
	}
	f(smith.curBlock, smith.curBlockPos)
	return types
}

func (smith *Smith) defineVar(id string, t *Type) {
	v := &Var{id: id, typ: t, block: smith.curBlock}
	b := smith.curBlock.sub[smith.curBlockPos]
	b.vars = append(b.vars, v)
}

func (smith *Smith) defineType(t *Type) {
	b := smith.curBlock.sub[smith.curBlockPos]
	b.types = append(b.types, t)
}

func (smith *Smith) materializeVar(t *Type) string {
	// TODO: generate var in another package
	id := smith.newId("Var")
	curBlock0 := smith.curBlock
	curBlockPos0 := smith.curBlockPos
	curBlockLen0 := len(smith.curBlock.sub)
	exprDepth0 := smith.exprDepth
	exprCount0 := smith.exprCount
	smith.exprDepth = 0
	smith.exprCount = 0
	defer func() {
		if smith.curBlock == curBlock0 {
			curBlockPos0 += len(smith.curBlock.sub) - curBlockLen0
		}
		smith.curBlock = curBlock0
		smith.curBlockPos = curBlockPos0
		smith.exprDepth = exprDepth0
		smith.exprCount = exprCount0
	}()
loop:
	for {
		if smith.curBlock.parent == nil {
			break
		}
		if !smith.curBlock.extendable || smith.curBlockPos < 0 {
			if smith.curBlock.subBlock == nil {
				smith.curBlockPos = len(smith.curBlock.parent.sub) - 2
			} else {
				smith.curBlockPos = -2
				for i, b1 := range smith.curBlock.parent.sub {
					if b1 == smith.curBlock.subBlock {
						smith.curBlockPos = i
						break
					}
				}
				if smith.curBlockPos == -2 {
					panic("bad")
				}
			}
			smith.curBlock = smith.curBlock.parent
			continue
		}
		if smith.rnd(3) == 0 {
			break
		}
		if smith.curBlockPos >= 0 {
			b := smith.curBlock.sub[smith.curBlockPos]
			for _, t1 := range b.types {
				if dependsOn(t, t1) {
					break loop
				}
			}
		}
		smith.curBlockPos--
	}
	if smith.curBlock.parent == nil {
		for i := smith.curPackage; i < NPackages; i++ {
			if smith.rndBool() || i == NPackages-1 || *singlepkg {
				if i == smith.curPackage {
					// emit global var into the current package
					smith.enterBlock(true)
					smith.line("var %v = %v", id, smith.rvalue(t))
					smith.packages[smith.curPackage].toplevVars = append(smith.packages[smith.curPackage].toplevVars, &Var{id: id, typ: t})
					smith.leaveBlock()
				} else {
					// emit global var into another package
					smith.packages[i].undefVars = append(smith.packages[i].undefVars, &Var{id: id, typ: t})
					smith.packages[smith.curPackage].imports[smith.packages[i].name] = true
					id = smith.packages[i].name + "." + id
				}
				break
			}
		}
	} else {
		// emit local var
		smith.line("%v := %v", id, smith.rvalue(t))
		smith.defineVar(id, t)
	}
	return id
}

func (smith *Smith) materializeFunc(rets []*Type) *Func {
	f := &Func{name: smith.newId("Func"), args: smith.atypeList(TraitGlobal), rets: rets}

	curBlock0 := smith.curBlock
	curBlockPos0 := smith.curBlockPos
	curFunc0 := smith.curFunc
	exprDepth0 := smith.exprDepth
	exprCount0 := smith.exprCount
	smith.exprDepth = 0
	smith.exprCount = 0
	defer func() {
		smith.curBlock = curBlock0
		smith.curBlockPos = curBlockPos0
		smith.curFunc = curFunc0
		smith.exprDepth = exprDepth0
		smith.exprCount = exprCount0
	}()

	if smith.rndBool() && !*singlepkg && smith.curPackage != NPackages-1 {
		for _, r1 := range rets {
			if dependsOn(r1, nil) {
				goto thisPackage
			}
		}
		for _, t := range f.args {
			if dependsOn(t, nil) {
				goto thisPackage
			}
		}
		// emit global var into another package
		newF := new(Func)
		*newF = *f
		smith.packages[smith.curPackage+1].undefFuncs = append(smith.packages[smith.curPackage+1].undefFuncs, newF)
		smith.packages[smith.curPackage].imports[smith.packages[smith.curPackage+1].name] = true
		f.name = smith.packages[smith.curPackage+1].name + "." + f.name
		return f
	}
thisPackage:
	smith.genToplevFunction(smith.curPackage, f)
	return f
}

func (smith *Smith) materializeGotoLabel() string {
	// TODO: move label up
	id := smith.newId("Label")

	curBlock0 := smith.curBlock
	curBlockPos0 := smith.curBlockPos
	curBlockLen0 := len(smith.curBlock.sub)
	defer func() {
		if smith.curBlock == curBlock0 {
			curBlockPos0 += len(smith.curBlock.sub) - curBlockLen0
		}
		smith.curBlock = curBlock0
		smith.curBlockPos = curBlockPos0
	}()

	for {
		if smith.curBlock.parent.funcBoundary && smith.curBlockPos <= 0 {
			break
		}
		if !smith.curBlock.extendable || smith.curBlockPos < 0 {
			if smith.curBlock.subBlock != nil {
				// we should have been stopped at func boundary
				panic("bad")
			}
			smith.curBlock = smith.curBlock.parent
			smith.curBlockPos = len(smith.curBlock.sub) - 2
			continue
		}
		if smith.rnd(3) == 0 {
			break
		}
		smith.curBlockPos--
	}

	smith.line("%v:", id)
	return id
}

func (smith *Smith) rnd(n int) int {
	return smith.rng.Intn(n)
}

func (smith *Smith) rndBool() bool {
	return smith.rnd(2) == 0
}

func (smith *Smith) choice(ch ...string) string {
	return ch[smith.rnd(len(ch))]
}

func (smith *Smith) newId(prefix string) string {
	if prefix[0] < 'A' || prefix[0] > 'Z' {
		panic("unexported id")
	}
	smith.idSeq++
	return fmt.Sprintf("%v%v", prefix, smith.idSeq)
}

func (smith *Smith) enterBlock(nonextendable bool) {
	b := &Block{parent: smith.curBlock, extendable: !nonextendable}
	b.isBreakable = smith.curBlock.isBreakable
	b.isContinuable = smith.curBlock.isContinuable
	smith.curBlock.sub = append(smith.curBlock.sub, b)
	smith.curBlock = b
	smith.curBlockPos = -1
}

func (smith *Smith) leaveBlock() {
	for _, b := range smith.curBlock.sub {
		for _, v := range b.vars {
			if !v.used {
				smith.line("_ = %v", v.id)
			}
		}
	}

	smith.curBlock = smith.curBlock.parent
	smith.curBlockPos = len(smith.curBlock.sub) - 1
}
