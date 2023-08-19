package keywords

//@rank("", type),rank("", func),rank("", var),rank("", const),rank("", import)

func _() {
	var test int //@rank(" //", int, interface)
	var tChan chan int
	var _ m //@complete(" //", map)
	var _ f //@complete(" //", func)
	var _ c //@complete(" //", chan)

	var _ str //@rank(" //", string, struct)

	type _ int //@rank(" //", interface, int)

	type _ str //@rank(" //", struct, string)

	switch test {
	case 1: // TODO: trying to complete case here will break because the parser wont return *ast.Ident
		b //@complete(" //", break)
	case 2:
		f //@complete(" //", fallthrough, for)
		r //@complete(" //", return)
		d //@complete(" //", default, defer)
		c //@complete(" //", case, const)
	}

	switch test.(type) {
	case fo: //@complete(":")
	case int:
		b //@complete(" //", break)
	case int32:
		f //@complete(" //", for)
		d //@complete(" //", default, defer)
		r //@complete(" //", return)
		c //@complete(" //", case, const)
	}

	select {
	case <-tChan:
		b //@complete(" //", break)
		c //@complete(" //", case, const)
	}

	for index := 0; index < test; index++ {
		c //@complete(" //", const, continue)
		b //@complete(" //", break)
	}

	for range []int{} {
		c //@complete(" //", const, continue)
		b //@complete(" //", break)
	}

	// Test function level keywords

	//Using 2 characters to test because map output order is random
	sw //@complete(" //", switch)
	se //@complete(" //", select)

	f //@complete(" //", for)
	d //@complete(" //", defer)
	g //@rank(" //", go),rank(" //", goto)
	r //@complete(" //", return)
	i //@complete(" //", if)
	e //@complete(" //", else)
	v //@complete(" //", var)
	c //@complete(" //", const)

	for i := r //@complete(" //", range)
}

/* package */ //@item(package, "package", "", "keyword")
/* import */ //@item(import, "import", "", "keyword")
/* func */ //@item(func, "func", "", "keyword")
/* type */ //@item(type, "type", "", "keyword")
/* var */ //@item(var, "var", "", "keyword")
/* const */ //@item(const, "const", "", "keyword")
/* break */ //@item(break, "break", "", "keyword")
/* default */ //@item(default, "default", "", "keyword")
/* case */ //@item(case, "case", "", "keyword")
/* defer */ //@item(defer, "defer", "", "keyword")
/* go */ //@item(go, "go", "", "keyword")
/* for */ //@item(for, "for", "", "keyword")
/* if */ //@item(if, "if", "", "keyword")
/* else */ //@item(else, "else", "", "keyword")
/* switch */ //@item(switch, "switch", "", "keyword")
/* select */ //@item(select, "select", "", "keyword")
/* fallthrough */ //@item(fallthrough, "fallthrough", "", "keyword")
/* continue */ //@item(continue, "continue", "", "keyword")
/* return */ //@item(return, "return", "", "keyword")
/* var */ //@item(var, "var", "", "keyword")
/* const */ //@item(const, "const", "", "keyword")
/* goto */ //@item(goto, "goto", "", "keyword")
/* struct */ //@item(struct, "struct", "", "keyword")
/* interface */ //@item(interface, "interface", "", "keyword")
/* map */ //@item(map, "map", "", "keyword")
/* func */ //@item(func, "func", "", "keyword")
/* chan */ //@item(chan, "chan", "", "keyword")
/* range */ //@item(range, "range", "", "keyword")
