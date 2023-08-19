package b

import (
	myFoo "golang.org/x/tools/internal/lsp/foo" //@mark(myFoo, "myFoo"),godef("myFoo", myFoo)
	"golang.org/x/tools/internal/lsp/godef/a"   //@mark(AImport, re"\".*\"")
)

type Embed struct {
	*a.A
	a.I
	a.S
}

func _() {
	e := Embed{}
	e.Hi()      //@hoverdef("Hi", AHi)
	e.B()       //@hoverdef("B", AB)
	e.Field     //@hoverdef("Field", AField)
	e.Field2    //@hoverdef("Field2", AField2)
	e.Hello()   //@hoverdef("Hello", AHello)
	e.Hey()     //@hoverdef("Hey", AHey)
	e.Goodbye() //@hoverdef("Goodbye", AGoodbye)
}

type aAlias = a.A //@mark(aAlias, "aAlias")

type S1 struct { //@S1
	F1     int //@mark(S1F1, "F1")
	S2         //@godef("S2", S2),mark(S1S2, "S2")
	a.A        //@godef("A", AString)
	aAlias     //@godef("a", aAlias)
}

type S2 struct { //@S2
	F1   string //@mark(S2F1, "F1")
	F2   int    //@mark(S2F2, "F2")
	*a.A        //@godef("A", AString),godef("a",AImport)
}

type S3 struct {
	F1 struct {
		a.A //@godef("A", AString)
	}
}

func Bar() {
	a.AStuff()  //@godef("AStuff", AStuff)
	var x S1    //@godef("S1", S1)
	_ = x.S2    //@godef("S2", S1S2)
	_ = x.F1    //@godef("F1", S1F1)
	_ = x.F2    //@godef("F2", S2F2)
	_ = x.S2.F1 //@godef("F1", S2F1)

	var _ *myFoo.StructFoo //@godef("myFoo", myFoo)
}

const X = 0 //@mark(bX, "X"),godef("X", bX)
