package unused

import (
	"go/types"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

type expectation bool

const (
	shouldBeUsed   = true
	shouldBeUnused = false
)

func (exp expectation) String() string {
	switch exp {
	case shouldBeUsed:
		return "used"
	case shouldBeUnused:
		return "unused"
	default:
		panic("unreachable")
	}
}

func check(t *testing.T, res *analysistest.Result) {
	type key struct {
		file string
		line int
	}
	want := map[key]expectation{}
	files := map[string]struct{}{}

	isTest := false
	for _, f := range res.Pass.Files {
		filename := res.Pass.Fset.Position(f.Pos()).Filename
		if strings.HasSuffix(filename, "_test.go") {
			isTest = true
			break
		}
	}
	for _, f := range res.Pass.Files {
		filename := res.Pass.Fset.Position(f.Pos()).Filename
		if !strings.HasSuffix(filename, ".go") {
			continue
		}
		files[filename] = struct{}{}
		for _, cgroup := range f.Comments {
		commentLoop:
			for _, c := range cgroup.List {
				text := strings.TrimPrefix(c.Text, "//")
				if text == c.Text {
					continue // not a //-comment
				}

				fields := strings.Fields(text)
				posn := res.Pass.Fset.Position(c.Pos())
				for _, field := range fields {
					switch field {
					case "used", "unused", "used_test", "unused_test":
					default:
						continue commentLoop
					}
				}
				for _, field := range fields {
					switch field {
					case "used":
						if !isTest {
							want[key{posn.Filename, posn.Line}] = shouldBeUsed
						}
					case "unused":
						if !isTest {
							want[key{posn.Filename, posn.Line}] = shouldBeUnused
						}
					case "used_test":
						if isTest {
							want[key{posn.Filename, posn.Line}] = shouldBeUsed
						}
					case "unused_test":
						if isTest {
							want[key{posn.Filename, posn.Line}] = shouldBeUnused
						}
					}
				}
			}
		}
	}

	checkObjs := func(objs []types.Object, state expectation) {
		for _, obj := range objs {
			posn := res.Pass.Fset.Position(obj.Pos())
			if _, ok := files[posn.Filename]; !ok {
				continue
			}

			k := key{posn.Filename, posn.Line}
			exp, ok := want[k]
			if !ok {
				t.Errorf("unexpected %s object at %s", state, posn)
				continue
			}
			delete(want, k)
			if state != exp {
				t.Errorf("object at %s should be %s but is %s", posn, exp, state)
			}
		}
	}
	ures := res.Result.(Result)
	checkObjs(ures.Used, shouldBeUsed)
	checkObjs(ures.Unused, shouldBeUnused)

	for key, b := range want {
		var exp string
		if b {
			exp = "used"
		} else {
			exp = "unused "
		}
		t.Errorf("did not see expected %s object %s:%d", exp, key.file, key.line)
	}
}

func TestAll(t *testing.T) {
	dirs := []string{
		"tests",
		"alias",
		"anonymous",
		"blank",
		"cgo",
		"consts",
		"conversion",
		"cyclic",
		"defer",
		"elem",
		"embedded_call",
		"embedding",
		"embedding2",
		"exported_fields",
		"exported_fields_main",
		"exported_method_test",
		"fields",
		"functions",
		"ignored",
		"interfaces",
		"interfaces2",
		"linkname",
		"main",
		"mapslice",
		"methods",
		"named",
		"nested",
		"nocopy",
		"nocopy-main",
		"pointer-type-embedding",
		"pointers",
		"quiet",
		"selectors",
		"switch_interface",
		"tests",
		"tests-main",
		"type-dedup",
		"type-dedup2",
		"type-dedup3",
		"types",
		"unused-argument",
		"unused_type",
		"variables",
	}

	results := analysistest.Run(t, analysistest.TestData(), Analyzer.Analyzer, dirs...)
	for _, res := range results {
		check(t, res)
	}
}
