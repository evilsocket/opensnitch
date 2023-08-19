// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packages_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	constantpkg "go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/tools/internal/packagesinternal"
	"golang.org/x/tools/internal/testenv"
)

// testCtx is canceled when the test binary is about to time out.
//
// If https://golang.org/issue/28135 is accepted, uses of this variable in test
// functions should be replaced by t.Context().
var testCtx = context.Background()

func TestMain(m *testing.M) {
	testenv.ExitIfSmallMachine()

	timeoutFlag := flag.Lookup("test.timeout")
	if timeoutFlag != nil {
		if d := timeoutFlag.Value.(flag.Getter).Get().(time.Duration); d != 0 {
			aBitShorter := d * 95 / 100
			var cancel context.CancelFunc
			testCtx, cancel = context.WithTimeout(testCtx, aBitShorter)
			defer cancel()
		}
	}

	os.Exit(m.Run())
}

func skipIfShort(t *testing.T, reason string) {
	if testing.Short() {
		t.Skipf("skipping slow test in short mode: %s", reason)
	}
}

// testAllOrModulesParallel tests f, in parallel, against all packagestest
// exporters in long mode, but only against the Modules exporter in short mode.
func testAllOrModulesParallel(t *testing.T, f func(*testing.T, packagestest.Exporter)) {
	t.Parallel()
	packagestest.TestAll(t, func(t *testing.T, exporter packagestest.Exporter) {
		t.Helper()

		switch exporter.Name() {
		case "Modules":
		case "GOPATH":
			if testing.Short() {
				t.Skipf("skipping GOPATH test in short mode")
			}
		default:
			t.Fatalf("unexpected exporter %q", exporter.Name())
		}

		t.Parallel()
		f(t, exporter)
	})
}

// TODO(adonovan): more test cases to write:
//
// - When the tests fail, make them print a 'cd & load' command
//   that will allow the maintainer to interact with the failing scenario.
// - errors in go-list metadata
// - a foo.test package that cannot be built for some reason (e.g.
//   import error) will result in a JSON blob with no name and a
//   nonexistent testmain file in GoFiles. Test that we handle this
//   gracefully.
// - test more Flags.
//
// LoadSyntax & LoadAllSyntax modes:
//   - Fset may be user-supplied or not.
//   - Packages.Info is correctly set.
//   - typechecker configuration is honored
//   - import cycles are gracefully handled in type checker.
//   - test typechecking of generated test main and cgo.

// The zero-value of Config has LoadFiles mode.
func TestLoadZeroConfig(t *testing.T) {
	testenv.NeedsGoPackages(t)
	t.Parallel()

	initial, err := packages.Load(nil, "hash")
	if err != nil {
		t.Fatal(err)
	}
	if len(initial) != 1 {
		t.Fatalf("got %s, want [hash]", initial)
	}
	hash := initial[0]
	// Even though the hash package has imports,
	// they are not reported.
	got := fmt.Sprintf("srcs=%v imports=%v", srcs(hash), hash.Imports)
	want := "srcs=[hash.go] imports=map[]"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestLoadImportsGraph(t *testing.T) { testAllOrModulesParallel(t, testLoadImportsGraph) }
func testLoadImportsGraph(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go":             `package a; const A = 1`,
			"b/b.go":             `package b; import ("golang.org/fake/a"; _ "container/list"); var B = a.A`,
			"c/c.go":             `package c; import (_ "golang.org/fake/b"; _ "unsafe")`,
			"c/c2.go":            "// +build ignore\n\n" + `package c; import _ "fmt"`,
			"subdir/d/d.go":      `package d`,
			"subdir/d/d_test.go": `package d; import _ "math/bits"`,
			"subdir/d/x_test.go": `package d_test; import _ "golang.org/fake/subdir/d"`, // TODO(adonovan): test bad import here
			"subdir/e/d.go":      `package e`,
			"e/e.go":             `package main; import _ "golang.org/fake/b"`,
			"e/e2.go":            `package main; import _ "golang.org/fake/c"`,
			"f/f.go":             `package f`,
		}}})
	defer exported.Cleanup()
	exported.Config.Mode = packages.LoadImports
	initial, err := packages.Load(exported.Config, "golang.org/fake/c", "golang.org/fake/subdir/d", "golang.org/fake/e")
	if err != nil {
		t.Fatal(err)
	}

	// Check graph topology.
	graph, _ := importGraph(initial)
	wantGraph := `
  container/list
  golang.org/fake/a
  golang.org/fake/b
* golang.org/fake/c
* golang.org/fake/e
* golang.org/fake/subdir/d
* golang.org/fake/subdir/d [golang.org/fake/subdir/d.test]
* golang.org/fake/subdir/d.test
* golang.org/fake/subdir/d_test [golang.org/fake/subdir/d.test]
  math/bits
  unsafe
  golang.org/fake/b -> container/list
  golang.org/fake/b -> golang.org/fake/a
  golang.org/fake/c -> golang.org/fake/b
  golang.org/fake/c -> unsafe
  golang.org/fake/e -> golang.org/fake/b
  golang.org/fake/e -> golang.org/fake/c
  golang.org/fake/subdir/d [golang.org/fake/subdir/d.test] -> math/bits
  golang.org/fake/subdir/d.test -> golang.org/fake/subdir/d [golang.org/fake/subdir/d.test]
  golang.org/fake/subdir/d.test -> golang.org/fake/subdir/d_test [golang.org/fake/subdir/d.test]
  golang.org/fake/subdir/d_test [golang.org/fake/subdir/d.test] -> golang.org/fake/subdir/d [golang.org/fake/subdir/d.test]
`[1:]

	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}

	exported.Config.Tests = true
	initial, err = packages.Load(exported.Config, "golang.org/fake/c", "golang.org/fake/subdir/d", "golang.org/fake/e")
	if err != nil {
		t.Fatal(err)
	}

	// Check graph topology.
	graph, all := importGraph(initial)
	wantGraph = `
  container/list
  golang.org/fake/a
  golang.org/fake/b
* golang.org/fake/c
* golang.org/fake/e
* golang.org/fake/subdir/d
* golang.org/fake/subdir/d [golang.org/fake/subdir/d.test]
* golang.org/fake/subdir/d.test
* golang.org/fake/subdir/d_test [golang.org/fake/subdir/d.test]
  math/bits
  unsafe
  golang.org/fake/b -> container/list
  golang.org/fake/b -> golang.org/fake/a
  golang.org/fake/c -> golang.org/fake/b
  golang.org/fake/c -> unsafe
  golang.org/fake/e -> golang.org/fake/b
  golang.org/fake/e -> golang.org/fake/c
  golang.org/fake/subdir/d [golang.org/fake/subdir/d.test] -> math/bits
  golang.org/fake/subdir/d.test -> golang.org/fake/subdir/d [golang.org/fake/subdir/d.test]
  golang.org/fake/subdir/d.test -> golang.org/fake/subdir/d_test [golang.org/fake/subdir/d.test]
  golang.org/fake/subdir/d_test [golang.org/fake/subdir/d.test] -> golang.org/fake/subdir/d [golang.org/fake/subdir/d.test]
`[1:]

	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}

	// Check node information: kind, name, srcs.
	for _, test := range []struct {
		id          string
		wantName    string
		wantKind    string
		wantSrcs    string
		wantIgnored string
	}{
		{"golang.org/fake/a", "a", "package", "a.go", ""},
		{"golang.org/fake/b", "b", "package", "b.go", ""},
		{"golang.org/fake/c", "c", "package", "c.go", "c2.go"}, // c2.go is ignored
		{"golang.org/fake/e", "main", "command", "e.go e2.go", ""},
		{"container/list", "list", "package", "list.go", ""},
		{"golang.org/fake/subdir/d", "d", "package", "d.go", ""},
		{"golang.org/fake/subdir/d.test", "main", "command", "0.go", ""},
		{"unsafe", "unsafe", "package", "", ""},
	} {
		p, ok := all[test.id]
		if !ok {
			t.Errorf("no package %s", test.id)
			continue
		}
		if p.Name != test.wantName {
			t.Errorf("%s.Name = %q, want %q", test.id, p.Name, test.wantName)
		}

		// kind
		var kind string
		if p.Name == "main" {
			kind += "command"
		} else {
			kind += "package"
		}
		if kind != test.wantKind {
			t.Errorf("%s.Kind = %q, want %q", test.id, kind, test.wantKind)
		}

		if srcs := strings.Join(srcs(p), " "); srcs != test.wantSrcs {
			t.Errorf("%s.Srcs = [%s], want [%s]", test.id, srcs, test.wantSrcs)
		}
		if ignored := strings.Join(cleanPaths(p.IgnoredFiles), " "); ignored != test.wantIgnored {
			t.Errorf("%s.Srcs = [%s], want [%s]", test.id, ignored, test.wantIgnored)
		}
	}

	// Test an ad-hoc package, analogous to "go run hello.go".
	if initial, err := packages.Load(exported.Config, exported.File("golang.org/fake", "c/c.go")); len(initial) == 0 {
		t.Errorf("failed to obtain metadata for ad-hoc package: %s", err)
	} else {
		got := fmt.Sprintf("%s %s", initial[0].ID, srcs(initial[0]))
		if want := "command-line-arguments [c.go]"; got != want {
			t.Errorf("oops: got %s, want %s", got, want)
		}
	}

	// Wildcards
	// See StdlibTest for effective test of "std" wildcard.
	// TODO(adonovan): test "all" returns everything in the current module.
	{
		// "..." (subdirectory)
		initial, err = packages.Load(exported.Config, "golang.org/fake/subdir/...")
		if err != nil {
			t.Fatal(err)
		}
		graph, _ = importGraph(initial)
		wantGraph = `
* golang.org/fake/subdir/d
* golang.org/fake/subdir/d [golang.org/fake/subdir/d.test]
* golang.org/fake/subdir/d.test
* golang.org/fake/subdir/d_test [golang.org/fake/subdir/d.test]
* golang.org/fake/subdir/e
  math/bits
  golang.org/fake/subdir/d [golang.org/fake/subdir/d.test] -> math/bits
  golang.org/fake/subdir/d.test -> golang.org/fake/subdir/d [golang.org/fake/subdir/d.test]
  golang.org/fake/subdir/d.test -> golang.org/fake/subdir/d_test [golang.org/fake/subdir/d.test]
  golang.org/fake/subdir/d_test [golang.org/fake/subdir/d.test] -> golang.org/fake/subdir/d [golang.org/fake/subdir/d.test]
`[1:]

		if graph != wantGraph {
			t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
		}
	}
}

func TestLoadImportsTestVariants(t *testing.T) {
	testAllOrModulesParallel(t, testLoadImportsTestVariants)
}
func testLoadImportsTestVariants(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go":       `package a; import _ "golang.org/fake/b"`,
			"b/b.go":       `package b`,
			"b/b_test.go":  `package b`,
			"b/bx_test.go": `package b_test; import _ "golang.org/fake/a"`,
		}}})
	defer exported.Cleanup()
	exported.Config.Mode = packages.LoadImports
	exported.Config.Tests = true

	initial, err := packages.Load(exported.Config, "golang.org/fake/a", "golang.org/fake/b")
	if err != nil {
		t.Fatal(err)
	}

	// Check graph topology.
	graph, _ := importGraph(initial)
	wantGraph := `
* golang.org/fake/a
  golang.org/fake/a [golang.org/fake/b.test]
* golang.org/fake/b
* golang.org/fake/b [golang.org/fake/b.test]
* golang.org/fake/b.test
* golang.org/fake/b_test [golang.org/fake/b.test]
  golang.org/fake/a -> golang.org/fake/b
  golang.org/fake/a [golang.org/fake/b.test] -> golang.org/fake/b [golang.org/fake/b.test]
  golang.org/fake/b.test -> golang.org/fake/b [golang.org/fake/b.test]
  golang.org/fake/b.test -> golang.org/fake/b_test [golang.org/fake/b.test]
  golang.org/fake/b_test [golang.org/fake/b.test] -> golang.org/fake/a [golang.org/fake/b.test]
`[1:]

	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}
}

func TestLoadAbsolutePath(t *testing.T) {
	t.Parallel()

	exported := packagestest.Export(t, packagestest.GOPATH, []packagestest.Module{{
		Name: "golang.org/gopatha",
		Files: map[string]interface{}{
			"a/a.go": `package a`,
		}}, {
		Name: "golang.org/gopathb",
		Files: map[string]interface{}{
			"b/b.go": `package b`,
		}}})
	defer exported.Cleanup()

	initial, err := packages.Load(exported.Config, filepath.Dir(exported.File("golang.org/gopatha", "a/a.go")), filepath.Dir(exported.File("golang.org/gopathb", "b/b.go")))
	if err != nil {
		t.Fatalf("failed to load imports: %v", err)
	}

	got := []string{}
	for _, p := range initial {
		got = append(got, p.ID)
	}
	sort.Strings(got)
	want := []string{"golang.org/gopatha/a", "golang.org/gopathb/b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("initial packages loaded: got [%s], want [%s]", got, want)
	}
}

func TestVendorImports(t *testing.T) {
	t.Parallel()

	exported := packagestest.Export(t, packagestest.GOPATH, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go":          `package a; import _ "b"; import _ "golang.org/fake/c";`,
			"a/vendor/b/b.go": `package b; import _ "golang.org/fake/c"`,
			"c/c.go":          `package c; import _ "b"`,
			"c/vendor/b/b.go": `package b`,
		}}})
	defer exported.Cleanup()
	exported.Config.Mode = packages.LoadImports
	initial, err := packages.Load(exported.Config, "golang.org/fake/a", "golang.org/fake/c")
	if err != nil {
		t.Fatal(err)
	}

	graph, all := importGraph(initial)
	wantGraph := `
* golang.org/fake/a
  golang.org/fake/a/vendor/b
* golang.org/fake/c
  golang.org/fake/c/vendor/b
  golang.org/fake/a -> golang.org/fake/a/vendor/b
  golang.org/fake/a -> golang.org/fake/c
  golang.org/fake/a/vendor/b -> golang.org/fake/c
  golang.org/fake/c -> golang.org/fake/c/vendor/b
`[1:]
	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}

	for _, test := range []struct {
		pattern     string
		wantImports string
	}{
		{"golang.org/fake/a", "b:golang.org/fake/a/vendor/b golang.org/fake/c:golang.org/fake/c"},
		{"golang.org/fake/c", "b:golang.org/fake/c/vendor/b"},
		{"golang.org/fake/a/vendor/b", "golang.org/fake/c:golang.org/fake/c"},
		{"golang.org/fake/c/vendor/b", ""},
	} {
		// Test the import paths.
		pkg := all[test.pattern]
		if imports := strings.Join(imports(pkg), " "); imports != test.wantImports {
			t.Errorf("package %q: got %s, want %s", test.pattern, imports, test.wantImports)
		}
	}
}

func imports(p *packages.Package) []string {
	if p == nil {
		return nil
	}
	keys := make([]string, 0, len(p.Imports))
	for k, v := range p.Imports {
		keys = append(keys, fmt.Sprintf("%s:%s", k, v.ID))
	}
	sort.Strings(keys)
	return keys
}

func TestConfigDir(t *testing.T) { testAllOrModulesParallel(t, testConfigDir) }
func testConfigDir(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go":   `package a; const Name = "a" `,
			"a/b/b.go": `package b; const Name = "a/b"`,
			"b/b.go":   `package b; const Name = "b"`,
		}}})
	defer exported.Cleanup()
	aDir := filepath.Dir(exported.File("golang.org/fake", "a/a.go"))
	bDir := filepath.Dir(exported.File("golang.org/fake", "b/b.go"))
	baseDir := filepath.Dir(aDir)

	for _, test := range []struct {
		dir     string
		pattern string
		want    string // value of Name constant
		fails   bool
	}{
		{dir: bDir, pattern: "golang.org/fake/a", want: `"a"`},
		{dir: bDir, pattern: "golang.org/fake/b", want: `"b"`},
		{dir: bDir, pattern: "./a", fails: true},
		{dir: bDir, pattern: "./b", fails: true},
		{dir: baseDir, pattern: "golang.org/fake/a", want: `"a"`},
		{dir: baseDir, pattern: "golang.org/fake/b", want: `"b"`},
		{dir: baseDir, pattern: "./a", want: `"a"`},
		{dir: baseDir, pattern: "./b", want: `"b"`},
		{dir: aDir, pattern: "golang.org/fake/a", want: `"a"`},
		{dir: aDir, pattern: "golang.org/fake/b", want: `"b"`},
		{dir: aDir, pattern: "./a", fails: true},
		{dir: aDir, pattern: "./b", want: `"a/b"`},
	} {
		exported.Config.Mode = packages.LoadSyntax // Use LoadSyntax to ensure that files can be opened.
		exported.Config.Dir = test.dir
		initial, err := packages.Load(exported.Config, test.pattern)
		var got string
		fails := false
		if err != nil {
			fails = true
		} else if len(initial) > 0 {
			if len(initial[0].Errors) > 0 {
				fails = true
			} else if c := constant(initial[0], "Name"); c != nil {
				got = c.Val().String()
			}
		}
		if got != test.want {
			t.Errorf("dir %q, pattern %q: got %s, want %s",
				test.dir, test.pattern, got, test.want)
		}
		if fails != test.fails {
			// TODO: remove when go#28023 is fixed
			if test.fails && strings.HasPrefix(test.pattern, "./") && exporter == packagestest.Modules {
				// Currently go list in module mode does not handle missing directories correctly.
				continue
			}
			t.Errorf("dir %q, pattern %q: error %v, want %v",
				test.dir, test.pattern, fails, test.fails)
		}
	}
}

func TestConfigFlags(t *testing.T) { testAllOrModulesParallel(t, testConfigFlags) }
func testConfigFlags(t *testing.T, exporter packagestest.Exporter) {
	// Test satisfying +build line tags, with -tags flag.
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			// package a
			"a/a.go": `package a; import _ "golang.org/fake/a/b"`,
			"a/b.go": `// +build tag

package a`,
			"a/c.go": `// +build tag tag2

package a`,
			"a/d.go": `// +build tag,tag2

package a`,
			// package a/b
			"a/b/a.go": `package b`,
			"a/b/b.go": `// +build tag

package b`,
		}}})
	defer exported.Cleanup()

	for _, test := range []struct {
		pattern        string
		tags           []string
		wantSrcs       string
		wantImportSrcs string
	}{
		{`golang.org/fake/a`, []string{}, "a.go", "a.go"},
		{`golang.org/fake/a`, []string{`-tags=tag`}, "a.go b.go c.go", "a.go b.go"},
		{`golang.org/fake/a`, []string{`-tags=tag2`}, "a.go c.go", "a.go"},
		{`golang.org/fake/a`, []string{`-tags=tag tag2`}, "a.go b.go c.go d.go", "a.go b.go"},
	} {
		exported.Config.Mode = packages.LoadImports
		exported.Config.BuildFlags = test.tags

		initial, err := packages.Load(exported.Config, test.pattern)
		if err != nil {
			t.Error(err)
			continue
		}
		if len(initial) != 1 {
			t.Errorf("test tags %v: pattern %s, expected 1 package, got %d packages.", test.tags, test.pattern, len(initial))
			continue
		}
		pkg := initial[0]
		if srcs := strings.Join(srcs(pkg), " "); srcs != test.wantSrcs {
			t.Errorf("test tags %v: srcs of package %s = [%s], want [%s]", test.tags, test.pattern, srcs, test.wantSrcs)
		}
		for path, ipkg := range pkg.Imports {
			if srcs := strings.Join(srcs(ipkg), " "); srcs != test.wantImportSrcs {
				t.Errorf("build tags %v: srcs of imported package %s = [%s], want [%s]", test.tags, path, srcs, test.wantImportSrcs)
			}
		}

	}
}

func TestLoadTypes(t *testing.T) { testAllOrModulesParallel(t, testLoadTypes) }
func testLoadTypes(t *testing.T, exporter packagestest.Exporter) {
	// In LoadTypes and LoadSyntax modes, the compiler will
	// fail to generate an export data file for c, because it has
	// a type error.  The loader should fall back loading a and c
	// from source, but use the export data for b.

	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import "golang.org/fake/b"; import "golang.org/fake/c"; const A = "a" + b.B + c.C`,
			"b/b.go": `package b; const B = "b"`,
			"c/c.go": `package c; const C = "c" + 1`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadTypes
	initial, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}

	graph, all := importGraph(initial)
	wantGraph := `
* golang.org/fake/a
  golang.org/fake/b
  golang.org/fake/c
  golang.org/fake/a -> golang.org/fake/b
  golang.org/fake/a -> golang.org/fake/c
`[1:]
	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}

	for _, id := range []string{
		"golang.org/fake/a",
		"golang.org/fake/b",
		"golang.org/fake/c",
	} {
		p := all[id]
		if p == nil {
			t.Errorf("missing package: %s", id)
			continue
		}
		if p.Types == nil {
			t.Errorf("missing types.Package for %s", p)
			continue
		} else if !p.Types.Complete() {
			t.Errorf("incomplete types.Package for %s", p)
		} else if p.TypesSizes == nil {
			t.Errorf("TypesSizes is not filled in for %s", p)
		}

	}
}

// TestLoadTypesBits is equivalent to TestLoadTypes except that it only requests
// the types using the NeedTypes bit.
func TestLoadTypesBits(t *testing.T) { testAllOrModulesParallel(t, testLoadTypesBits) }
func testLoadTypesBits(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import "golang.org/fake/b"; const A = "a" + b.B`,
			"b/b.go": `package b; import "golang.org/fake/c"; const B = "b" + c.C`,
			"c/c.go": `package c; import "golang.org/fake/d"; const C = "c" + d.D`,
			"d/d.go": `package d; import "golang.org/fake/e"; const D = "d" + e.E`,
			"e/e.go": `package e; import "golang.org/fake/f"; const E = "e" + f.F`,
			"f/f.go": `package f; const F = "f"`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.NeedTypes | packages.NeedImports
	initial, err := packages.Load(exported.Config, "golang.org/fake/a", "golang.org/fake/c")
	if err != nil {
		t.Fatal(err)
	}

	graph, all := importGraph(initial)
	wantGraph := `
* golang.org/fake/a
  golang.org/fake/b
* golang.org/fake/c
  golang.org/fake/d
  golang.org/fake/e
  golang.org/fake/f
  golang.org/fake/a -> golang.org/fake/b
  golang.org/fake/b -> golang.org/fake/c
  golang.org/fake/c -> golang.org/fake/d
  golang.org/fake/d -> golang.org/fake/e
  golang.org/fake/e -> golang.org/fake/f
`[1:]
	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}

	for _, test := range []struct {
		id string
	}{
		{"golang.org/fake/a"},
		{"golang.org/fake/b"},
		{"golang.org/fake/c"},
		{"golang.org/fake/d"},
		{"golang.org/fake/e"},
		{"golang.org/fake/f"},
	} {
		p := all[test.id]
		if p == nil {
			t.Errorf("missing package: %s", test.id)
			continue
		}
		if p.Types == nil {
			t.Errorf("missing types.Package for %s", p)
			continue
		}
		// We don't request the syntax, so we shouldn't get it.
		if p.Syntax != nil {
			t.Errorf("Syntax unexpectedly provided for %s", p)
		}
		if p.Errors != nil {
			t.Errorf("errors in package: %s: %s", p, p.Errors)
		}
	}

	// Check value of constant.
	aA := constant(all["golang.org/fake/a"], "A")
	if aA == nil {
		t.Fatalf("a.A: got nil")
	}
	if got, want := fmt.Sprintf("%v %v", aA, aA.Val()), `const golang.org/fake/a.A untyped string "abcdef"`; got != want {
		t.Errorf("a.A: got %s, want %s", got, want)
	}
}

func TestLoadSyntaxOK(t *testing.T) { testAllOrModulesParallel(t, testLoadSyntaxOK) }
func testLoadSyntaxOK(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import "golang.org/fake/b"; const A = "a" + b.B`,
			"b/b.go": `package b; import "golang.org/fake/c"; const B = "b" + c.C`,
			"c/c.go": `package c; import "golang.org/fake/d"; const C = "c" + d.D`,
			"d/d.go": `package d; import "golang.org/fake/e"; const D = "d" + e.E`,
			"e/e.go": `package e; import "golang.org/fake/f"; const E = "e" + f.F`,
			"f/f.go": `package f; const F = "f"`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadSyntax
	initial, err := packages.Load(exported.Config, "golang.org/fake/a", "golang.org/fake/c")
	if err != nil {
		t.Fatal(err)
	}

	graph, all := importGraph(initial)
	wantGraph := `
* golang.org/fake/a
  golang.org/fake/b
* golang.org/fake/c
  golang.org/fake/d
  golang.org/fake/e
  golang.org/fake/f
  golang.org/fake/a -> golang.org/fake/b
  golang.org/fake/b -> golang.org/fake/c
  golang.org/fake/c -> golang.org/fake/d
  golang.org/fake/d -> golang.org/fake/e
  golang.org/fake/e -> golang.org/fake/f
`[1:]
	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}

	for _, test := range []struct {
		id           string
		wantSyntax   bool
		wantComplete bool
	}{
		{"golang.org/fake/a", true, true},   // source package
		{"golang.org/fake/b", true, true},   // source package because depends on initial package
		{"golang.org/fake/c", true, true},   // source package
		{"golang.org/fake/d", false, true},  // export data package
		{"golang.org/fake/e", false, false}, // export data package
		{"golang.org/fake/f", false, false}, // export data package
	} {
		// TODO(matloob): LoadSyntax and LoadAllSyntax are now equivalent, wantSyntax and wantComplete
		// are true for all packages in the transitive dependency set. Add test cases on the individual
		// Need* fields to check the equivalents on the new API.
		p := all[test.id]
		if p == nil {
			t.Errorf("missing package: %s", test.id)
			continue
		}
		if p.Types == nil {
			t.Errorf("missing types.Package for %s", p)
			continue
		} else if p.Types.Complete() != test.wantComplete {
			if test.wantComplete {
				t.Errorf("incomplete types.Package for %s", p)
			} else {
				t.Errorf("unexpected complete types.Package for %s", p)
			}
		}
		if (p.Syntax != nil) != test.wantSyntax {
			if test.wantSyntax {
				t.Errorf("missing ast.Files for %s", p)
			} else {
				t.Errorf("unexpected ast.Files for for %s", p)
			}
		}
		if p.Errors != nil {
			t.Errorf("errors in package: %s: %s", p, p.Errors)
		}
	}

	// Check value of constant.
	aA := constant(all["golang.org/fake/a"], "A")
	if aA == nil {
		t.Fatalf("a.A: got nil")
	}
	if got, want := fmt.Sprintf("%v %v", aA, aA.Val()), `const golang.org/fake/a.A untyped string "abcdef"`; got != want {
		t.Errorf("a.A: got %s, want %s", got, want)
	}
}

func TestLoadDiamondTypes(t *testing.T) { testAllOrModulesParallel(t, testLoadDiamondTypes) }
func testLoadDiamondTypes(t *testing.T, exporter packagestest.Exporter) {
	// We make a diamond dependency and check the type d.D is the same through both paths
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import ("golang.org/fake/b"; "golang.org/fake/c"); var _ = b.B == c.C`,
			"b/b.go": `package b; import "golang.org/fake/d"; var B d.D`,
			"c/c.go": `package c; import "golang.org/fake/d"; var C d.D`,
			"d/d.go": `package d; type D int`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadSyntax
	initial, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}
	packages.Visit(initial, nil, func(pkg *packages.Package) {
		for _, err := range pkg.Errors {
			t.Errorf("package %s: %v", pkg.ID, err)
		}
	})

	graph, _ := importGraph(initial)
	wantGraph := `
* golang.org/fake/a
  golang.org/fake/b
  golang.org/fake/c
  golang.org/fake/d
  golang.org/fake/a -> golang.org/fake/b
  golang.org/fake/a -> golang.org/fake/c
  golang.org/fake/b -> golang.org/fake/d
  golang.org/fake/c -> golang.org/fake/d
`[1:]
	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}
}

func TestLoadSyntaxError(t *testing.T) { testAllOrModulesParallel(t, testLoadSyntaxError) }
func testLoadSyntaxError(t *testing.T, exporter packagestest.Exporter) {
	// A type error in a lower-level package (e) prevents go list
	// from producing export data for all packages that depend on it
	// [a-e]. Only f should be loaded from export data, and the rest
	// should be IllTyped.
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import "golang.org/fake/b"; const A = "a" + b.B`,
			"b/b.go": `package b; import "golang.org/fake/c"; const B = "b" + c.C`,
			"c/c.go": `package c; import "golang.org/fake/d"; const C = "c" + d.D`,
			"d/d.go": `package d; import "golang.org/fake/e"; const D = "d" + e.E`,
			"e/e.go": `package e; import "golang.org/fake/f"; const E = "e" + f.F + 1`, // type error
			"f/f.go": `package f; const F = "f"`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadSyntax
	initial, err := packages.Load(exported.Config, "golang.org/fake/a", "golang.org/fake/c")
	if err != nil {
		t.Fatal(err)
	}

	all := make(map[string]*packages.Package)
	packages.Visit(initial, nil, func(p *packages.Package) {
		all[p.ID] = p
	})

	for _, test := range []struct {
		id           string
		wantSyntax   bool
		wantIllTyped bool
	}{
		{"golang.org/fake/a", true, true},
		{"golang.org/fake/b", true, true},
		{"golang.org/fake/c", true, true},
		{"golang.org/fake/d", true, true},
		{"golang.org/fake/e", true, true},
		{"golang.org/fake/f", false, false},
	} {
		p := all[test.id]
		if p == nil {
			t.Errorf("missing package: %s", test.id)
			continue
		}
		if p.Types == nil {
			t.Errorf("missing types.Package for %s", p)
			continue
		} else if !p.Types.Complete() {
			t.Errorf("incomplete types.Package for %s", p)
		}
		if (p.Syntax != nil) != test.wantSyntax {
			if test.wantSyntax {
				t.Errorf("missing ast.Files for %s", test.id)
			} else {
				t.Errorf("unexpected ast.Files for for %s", test.id)
			}
		}
		if p.IllTyped != test.wantIllTyped {
			t.Errorf("IllTyped was %t for %s", p.IllTyped, test.id)
		}
	}

	// Check value of constant.
	aA := constant(all["golang.org/fake/a"], "A")
	if aA == nil {
		t.Fatalf("a.A: got nil")
	}
	if got, want := aA.String(), `const golang.org/fake/a.A invalid type`; got != want {
		t.Errorf("a.A: got %s, want %s", got, want)
	}
}

// This function tests use of the ParseFile hook to modify
// the AST after parsing.
func TestParseFileModifyAST(t *testing.T) { testAllOrModulesParallel(t, testParseFileModifyAST) }
func testParseFileModifyAST(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; const A = "a" `,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadAllSyntax
	exported.Config.ParseFile = func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
		const mode = parser.AllErrors | parser.ParseComments
		f, err := parser.ParseFile(fset, filename, src, mode)
		// modify AST to change `const A = "a"` to `const A = "b"`
		spec := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.ValueSpec)
		spec.Values[0].(*ast.BasicLit).Value = `"b"`
		return f, err
	}
	initial, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Error(err)
	}

	// Check value of a.A has been set to "b"
	a := initial[0]
	got := constant(a, "A").Val().String()
	if got != `"b"` {
		t.Errorf("a.A: got %s, want %s", got, `"b"`)
	}
}

func TestAdHocPackagesBadImport(t *testing.T) {
	t.Parallel()

	// This test doesn't use packagestest because we are testing ad-hoc packages,
	// which are outside of $GOPATH and outside of a module.
	tmp, err := ioutil.TempDir("", "a")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	filename := filepath.Join(tmp, "a.go")
	content := []byte(`package a
import _ "badimport"
const A = 1
`)
	if err := ioutil.WriteFile(filename, content, 0775); err != nil {
		t.Fatal(err)
	}

	// Make sure that the user's value of GO111MODULE does not affect test results.
	for _, go111module := range []string{"off", "auto", "on"} {
		config := &packages.Config{
			Env:  append(os.Environ(), "GOPACKAGESDRIVER=off", fmt.Sprintf("GO111MODULE=%s", go111module)),
			Dir:  tmp,
			Mode: packages.LoadAllSyntax,
			Logf: t.Logf,
		}
		initial, err := packages.Load(config, fmt.Sprintf("file=%s", filename))
		if err != nil {
			t.Error(err)
		}
		if len(initial) == 0 {
			t.Fatalf("no packages for %s with GO111MODULE=%s", filename, go111module)
		}
		// Check value of a.A.
		a := initial[0]
		// There's an error because there's a bad import.
		aA := constant(a, "A")
		if aA == nil {
			t.Errorf("a.A: got nil")
			return
		}
		got := aA.Val().String()
		if want := "1"; got != want {
			t.Errorf("a.A: got %s, want %s", got, want)
		}
	}
}

func TestLoadAllSyntaxImportErrors(t *testing.T) {
	testAllOrModulesParallel(t, testLoadAllSyntaxImportErrors)
}
func testLoadAllSyntaxImportErrors(t *testing.T, exporter packagestest.Exporter) {
	// TODO(matloob): Remove this once go list -e -compiled is fixed.
	// See https://golang.org/issue/26755
	t.Skip("go list -compiled -e fails with non-zero exit status for empty packages")

	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"unicycle/unicycle.go": `package unicycle; import _ "unicycle"`,
			"bicycle1/bicycle1.go": `package bicycle1; import _ "bicycle2"`,
			"bicycle2/bicycle2.go": `package bicycle2; import _ "bicycle1"`,
			"bad/bad.go":           `not a package declaration`,
			"empty/README.txt":     `not a go file`,
			"root/root.go": `package root
import (
	_ "bicycle1"
	_ "unicycle"
	_ "nonesuch"
	_ "empty"
	_ "bad"
)`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadAllSyntax
	initial, err := packages.Load(exported.Config, "root")
	if err != nil {
		t.Fatal(err)
	}

	// Cycle-forming edges are removed from the graph:
	// 	bicycle2 -> bicycle1
	//      unicycle -> unicycle
	graph, all := importGraph(initial)
	wantGraph := `
  bicycle1
  bicycle2
* root
  unicycle
  bicycle1 -> bicycle2
  root -> bicycle1
  root -> unicycle
`[1:]
	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}
	for _, test := range []struct {
		id       string
		wantErrs []string
	}{
		{"bicycle1", nil},
		{"bicycle2", []string{
			"could not import bicycle1 (import cycle: [root bicycle1 bicycle2])",
		}},
		{"unicycle", []string{
			"could not import unicycle (import cycle: [root unicycle])",
		}},
		{"root", []string{
			`could not import bad (missing package: "bad")`,
			`could not import empty (missing package: "empty")`,
			`could not import nonesuch (missing package: "nonesuch")`,
		}},
	} {
		p := all[test.id]
		if p == nil {
			t.Errorf("missing package: %s", test.id)
			continue
		}
		if p.Types == nil {
			t.Errorf("missing types.Package for %s", test.id)
		}
		if p.Syntax == nil {
			t.Errorf("missing ast.Files for %s", test.id)
		}
		if !p.IllTyped {
			t.Errorf("IllTyped was false for %s", test.id)
		}
		if errs := errorMessages(p.Errors); !reflect.DeepEqual(errs, test.wantErrs) {
			t.Errorf("in package %s, got errors %s, want %s", p, errs, test.wantErrs)
		}
	}
}

func TestAbsoluteFilenames(t *testing.T) { testAllOrModulesParallel(t, testAbsoluteFilenames) }
func testAbsoluteFilenames(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go":          `package a; const A = 1`,
			"b/b.go":          `package b; import ("golang.org/fake/a"; _ "errors"); var B = a.A`,
			"b/vendor/a/a.go": `package a; const A = 1`,
			"c/c.go":          `package c; import (_ "golang.org/fake/b"; _ "unsafe")`,
			"c/c2.go":         "// +build ignore\n\n" + `package c; import _ "fmt"`,
			"subdir/d/d.go":   `package d`,
			"subdir/e/d.go":   `package e`,
			"e/e.go":          `package main; import _ "golang.org/fake/b"`,
			"e/e2.go":         `package main; import _ "golang.org/fake/c"`,
			"f/f.go":          `package f`,
			"f/f.s":           ``,
		}}})
	defer exported.Cleanup()
	exported.Config.Dir = filepath.Dir(filepath.Dir(exported.File("golang.org/fake", "a/a.go")))

	checkFile := func(filename string) {
		if !filepath.IsAbs(filename) {
			t.Errorf("filename is not absolute: %s", filename)
		}
		if _, err := os.Stat(filename); err != nil {
			t.Errorf("stat error, %s: %v", filename, err)
		}
	}

	for _, test := range []struct {
		pattern string
		want    string
	}{
		// Import paths
		{"golang.org/fake/a", "a.go"},
		{"golang.org/fake/b/vendor/a", "a.go"},
		{"golang.org/fake/b", "b.go"},
		{"golang.org/fake/c", "c.go"},
		{"golang.org/fake/subdir/d", "d.go"},
		{"golang.org/fake/subdir/e", "d.go"},
		{"golang.org/fake/e", "e.go e2.go"},
		{"golang.org/fake/f", "f.go f.s"},
		// Relative paths
		{"./a", "a.go"},
		{"./b/vendor/a", "a.go"},
		{"./b", "b.go"},
		{"./c", "c.go"},
		{"./subdir/d", "d.go"},
		{"./subdir/e", "d.go"},
		{"./e", "e.go e2.go"},
		{"./f", "f.go f.s"},
	} {
		exported.Config.Mode = packages.LoadFiles
		pkgs, err := packages.Load(exported.Config, test.pattern)
		if err != nil {
			t.Errorf("pattern %s: %v", test.pattern, err)
			continue
		}

		if got := strings.Join(srcs(pkgs[0]), " "); got != test.want {
			t.Errorf("in package %s, got %s, want %s", test.pattern, got, test.want)
		}

		// Test that files in all packages exist and are absolute paths.
		_, all := importGraph(pkgs)
		for _, pkg := range all {
			for _, filename := range pkg.GoFiles {
				checkFile(filename)
			}
			for _, filename := range pkg.OtherFiles {
				checkFile(filename)
			}
			for _, filename := range pkg.IgnoredFiles {
				checkFile(filename)
			}
		}
	}
}

func TestContains(t *testing.T) { testAllOrModulesParallel(t, testContains) }
func testContains(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import "golang.org/fake/b"`,
			"b/b.go": `package b; import "golang.org/fake/c"`,
			"c/c.go": `package c`,
		}}})
	defer exported.Cleanup()
	bFile := exported.File("golang.org/fake", "b/b.go")
	exported.Config.Mode = packages.LoadImports
	initial, err := packages.Load(exported.Config, "file="+bFile)
	if err != nil {
		t.Fatal(err)
	}

	graph, _ := importGraph(initial)
	wantGraph := `
* golang.org/fake/b
  golang.org/fake/c
  golang.org/fake/b -> golang.org/fake/c
`[1:]
	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}
}

// This test ensures that the effective GOARCH variable in the
// application determines the Sizes function used by the type checker.
// This behavior is a stop-gap until we make the build system's query
// tool report the correct sizes function for the actual configuration.
func TestSizes(t *testing.T) { testAllOrModulesParallel(t, testSizes) }
func testSizes(t *testing.T, exporter packagestest.Exporter) {
	// Only run this test on operating systems that have both an amd64 and 386 port.
	switch runtime.GOOS {
	case "linux", "windows", "freebsd", "openbsd", "netbsd", "android":
	default:
		t.Skipf("skipping test on %s", runtime.GOOS)
	}

	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import "unsafe"; const WordSize = 8*unsafe.Sizeof(int(0))`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadSyntax
	savedEnv := exported.Config.Env
	for arch, wantWordSize := range map[string]int64{"386": 32, "amd64": 64} {
		exported.Config.Env = append(savedEnv, "GOARCH="+arch)
		initial, err := packages.Load(exported.Config, "golang.org/fake/a")
		if err != nil {
			t.Fatal(err)
		}
		if packages.PrintErrors(initial) > 0 {
			t.Fatal("there were errors")
		}
		gotWordSize, _ := constantpkg.Int64Val(constant(initial[0], "WordSize").Val())
		if gotWordSize != wantWordSize {
			t.Errorf("for GOARCH=%s, got word size %d, want %d", arch, gotWordSize, wantWordSize)
		}
	}
}

// TestContainsFallbackSticks ensures that when there are both contains and non-contains queries
// the decision whether to fallback to the pre-1.11 go list sticks across both sets of calls to
// go list.
func TestContainsFallbackSticks(t *testing.T) {
	testAllOrModulesParallel(t, testContainsFallbackSticks)
}
func testContainsFallbackSticks(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import "golang.org/fake/b"`,
			"b/b.go": `package b; import "golang.org/fake/c"`,
			"c/c.go": `package c`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadImports
	bFile := exported.File("golang.org/fake", "b/b.go")
	initial, err := packages.Load(exported.Config, "golang.org/fake/a", "file="+bFile)
	if err != nil {
		t.Fatal(err)
	}

	graph, _ := importGraph(initial)
	wantGraph := `
* golang.org/fake/a
* golang.org/fake/b
  golang.org/fake/c
  golang.org/fake/a -> golang.org/fake/b
  golang.org/fake/b -> golang.org/fake/c
`[1:]
	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}
}

// Test that Load with no patterns is equivalent to loading "." via the golist
// driver.
func TestNoPatterns(t *testing.T) { testAllOrModulesParallel(t, testNoPatterns) }
func testNoPatterns(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go":   `package a;`,
			"a/b/b.go": `package b;`,
		}}})
	defer exported.Cleanup()

	aDir := filepath.Dir(exported.File("golang.org/fake", "a/a.go"))
	exported.Config.Dir = aDir

	initial, err := packages.Load(exported.Config)
	if err != nil {
		t.Fatal(err)
	}
	if len(initial) != 1 || initial[0].Name != "a" {
		t.Fatalf(`Load() = %v, wanted just the package in the current directory`, initial)
	}
}

func TestJSON(t *testing.T) { testAllOrModulesParallel(t, testJSON) }
func testJSON(t *testing.T, exporter packagestest.Exporter) {
	//TODO: add in some errors
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; const A = 1`,
			"b/b.go": `package b; import "golang.org/fake/a"; var B = a.A`,
			"c/c.go": `package c; import "golang.org/fake/b" ; var C = b.B`,
			"d/d.go": `package d; import "golang.org/fake/b" ; var D = b.B`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadImports
	initial, err := packages.Load(exported.Config, "golang.org/fake/c", "golang.org/fake/d")
	if err != nil {
		t.Fatal(err)
	}

	// Visit and print all packages.
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "\t")
	packages.Visit(initial, nil, func(pkg *packages.Package) {
		// trim the source lists for stable results
		pkg.GoFiles = cleanPaths(pkg.GoFiles)
		pkg.CompiledGoFiles = cleanPaths(pkg.CompiledGoFiles)
		pkg.OtherFiles = cleanPaths(pkg.OtherFiles)
		pkg.IgnoredFiles = cleanPaths(pkg.IgnoredFiles)
		if err := enc.Encode(pkg); err != nil {
			t.Fatal(err)
		}
	})

	wantJSON := `
{
	"ID": "golang.org/fake/a",
	"Name": "a",
	"PkgPath": "golang.org/fake/a",
	"GoFiles": [
		"a.go"
	],
	"CompiledGoFiles": [
		"a.go"
	]
}
{
	"ID": "golang.org/fake/b",
	"Name": "b",
	"PkgPath": "golang.org/fake/b",
	"GoFiles": [
		"b.go"
	],
	"CompiledGoFiles": [
		"b.go"
	],
	"Imports": {
		"golang.org/fake/a": "golang.org/fake/a"
	}
}
{
	"ID": "golang.org/fake/c",
	"Name": "c",
	"PkgPath": "golang.org/fake/c",
	"GoFiles": [
		"c.go"
	],
	"CompiledGoFiles": [
		"c.go"
	],
	"Imports": {
		"golang.org/fake/b": "golang.org/fake/b"
	}
}
{
	"ID": "golang.org/fake/d",
	"Name": "d",
	"PkgPath": "golang.org/fake/d",
	"GoFiles": [
		"d.go"
	],
	"CompiledGoFiles": [
		"d.go"
	],
	"Imports": {
		"golang.org/fake/b": "golang.org/fake/b"
	}
}
`[1:]

	if buf.String() != wantJSON {
		t.Errorf("wrong JSON: got <<%s>>, want <<%s>>", buf.String(), wantJSON)
	}
	// now decode it again
	var decoded []*packages.Package
	dec := json.NewDecoder(buf)
	for dec.More() {
		p := new(packages.Package)
		if err := dec.Decode(p); err != nil {
			t.Fatal(err)
		}
		decoded = append(decoded, p)
	}
	if len(decoded) != 4 {
		t.Fatalf("got %d packages, want 4", len(decoded))
	}
	for i, want := range []*packages.Package{{
		ID:   "golang.org/fake/a",
		Name: "a",
	}, {
		ID:   "golang.org/fake/b",
		Name: "b",
		Imports: map[string]*packages.Package{
			"golang.org/fake/a": {ID: "golang.org/fake/a"},
		},
	}, {
		ID:   "golang.org/fake/c",
		Name: "c",
		Imports: map[string]*packages.Package{
			"golang.org/fake/b": {ID: "golang.org/fake/b"},
		},
	}, {
		ID:   "golang.org/fake/d",
		Name: "d",
		Imports: map[string]*packages.Package{
			"golang.org/fake/b": {ID: "golang.org/fake/b"},
		},
	}} {
		got := decoded[i]
		if got.ID != want.ID {
			t.Errorf("Package %d has ID %q want %q", i, got.ID, want.ID)
		}
		if got.Name != want.Name {
			t.Errorf("Package %q has Name %q want %q", got.ID, got.Name, want.Name)
		}
		if len(got.Imports) != len(want.Imports) {
			t.Errorf("Package %q has %d imports want %d", got.ID, len(got.Imports), len(want.Imports))
			continue
		}
		for path, ipkg := range got.Imports {
			if want.Imports[path] == nil {
				t.Errorf("Package %q has unexpected import %q", got.ID, path)
				continue
			}
			if want.Imports[path].ID != ipkg.ID {
				t.Errorf("Package %q import %q is %q want %q", got.ID, path, ipkg.ID, want.Imports[path].ID)
			}
		}
	}
}

func TestRejectInvalidQueries(t *testing.T) {
	t.Parallel()

	queries := []string{"key=", "key=value"}
	cfg := &packages.Config{
		Mode: packages.LoadImports,
		Env:  append(os.Environ(), "GO111MODULE=off", "GOPACKAGESDRIVER=off"),
	}
	for _, q := range queries {
		if _, err := packages.Load(cfg, q); err == nil {
			t.Errorf("packages.Load(%q) succeeded. Expected \"invalid query type\" error", q)
		} else if !strings.Contains(err.Error(), "invalid query type") {
			t.Errorf("packages.Load(%q): got error %v, want \"invalid query type\" error", q, err)
		}
	}
}

func TestPatternPassthrough(t *testing.T) { testAllOrModulesParallel(t, testPatternPassthrough) }
func testPatternPassthrough(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a;`,
		}}})
	defer exported.Cleanup()

	initial, err := packages.Load(exported.Config, "pattern=a")
	if err != nil {
		t.Fatal(err)
	}

	graph, _ := importGraph(initial)
	wantGraph := `
* a
`[1:]
	if graph != wantGraph {
		t.Errorf("wrong import graph: got <<%s>>, want <<%s>>", graph, wantGraph)
	}

}

func TestConfigDefaultEnv(t *testing.T) {
	// packagestest.TestAll instead of testAllOrModulesParallel because this test
	// can't be parallelized (it modifies the environment).
	packagestest.TestAll(t, testConfigDefaultEnv)
}
func testConfigDefaultEnv(t *testing.T, exporter packagestest.Exporter) {
	const driverJSON = `{
  "Roots": ["gopackagesdriver"],
  "Packages": [{"ID": "gopackagesdriver", "Name": "gopackagesdriver"}]
}`
	var (
		pathKey      string
		driverScript packagestest.Writer
	)
	switch runtime.GOOS {
	case "android":
		t.Skip("doesn't run on android")
	case "windows":
		// TODO(jayconrod): write an equivalent batch script for windows.
		// Hint: "type" can be used to read a file to stdout.
		t.Skip("test requires sh")
	case "plan9":
		pathKey = "path"
		driverScript = packagestest.Script(`#!/bin/rc

cat <<'EOF'
` + driverJSON + `
EOF
`)
	default:
		pathKey = "PATH"
		driverScript = packagestest.Script(`#!/bin/sh

cat - <<'EOF'
` + driverJSON + `
EOF
`)
	}
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"bin/gopackagesdriver": driverScript,
			"golist/golist.go":     "package golist",
		}}})
	defer exported.Cleanup()
	driver := exported.File("golang.org/fake", "bin/gopackagesdriver")
	binDir := filepath.Dir(driver)
	if err := os.Chmod(driver, 0755); err != nil {
		t.Fatal(err)
	}

	path, ok := os.LookupEnv(pathKey)
	var pathWithDriver string
	if ok {
		pathWithDriver = binDir + string(os.PathListSeparator) + path
	} else {
		pathWithDriver = binDir
	}
	for _, test := range []struct {
		desc    string
		path    string
		driver  string
		wantIDs string
	}{
		{
			desc:    "driver_off",
			path:    pathWithDriver,
			driver:  "off",
			wantIDs: "[golist]",
		}, {
			desc:    "driver_unset",
			path:    pathWithDriver,
			driver:  "",
			wantIDs: "[gopackagesdriver]",
		}, {
			desc:    "driver_set",
			path:    "",
			driver:  driver,
			wantIDs: "[gopackagesdriver]",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			oldPath := os.Getenv(pathKey)
			os.Setenv(pathKey, test.path)
			defer os.Setenv(pathKey, oldPath)
			// Clone exported.Config
			config := exported.Config
			config.Env = append([]string{}, exported.Config.Env...)
			config.Env = append(config.Env, "GOPACKAGESDRIVER="+test.driver)
			pkgs, err := packages.Load(exported.Config, "golist")
			if err != nil {
				t.Fatal(err)
			}

			gotIds := make([]string, len(pkgs))
			for i, pkg := range pkgs {
				gotIds[i] = pkg.ID
			}
			if fmt.Sprint(pkgs) != test.wantIDs {
				t.Errorf("got %v; want %v", gotIds, test.wantIDs)
			}
		})
	}
}

// This test that a simple x test package layout loads correctly.
// There was a bug in go list where it returned multiple copies of the same
// package (specifically in this case of golang.org/fake/a), and this triggered
// a bug in go/packages where it would leave an empty entry in the root package
// list. This would then cause a nil pointer crash.
// This bug was triggered by the simple package layout below, and thus this
// test will make sure the bug remains fixed.
func TestBasicXTest(t *testing.T) { testAllOrModulesParallel(t, testBasicXTest) }
func testBasicXTest(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go":      `package a;`,
			"a/a_test.go": `package a_test;`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadFiles
	exported.Config.Tests = true
	_, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}
}

func TestErrorMissingFile(t *testing.T) { testAllOrModulesParallel(t, testErrorMissingFile) }
func testErrorMissingFile(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a_test.go": `package a;`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadSyntax
	exported.Config.Tests = false
	pkgs, err := packages.Load(exported.Config, "missing.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) == 0 && runtime.GOOS == "windows" {
		t.Skip("Issue #31344: the ad-hoc command-line-arguments package isn't created on windows")
	}
	if len(pkgs) != 1 || (pkgs[0].PkgPath != "command-line-arguments" && pkgs[0].PkgPath != "missing.go") {
		t.Fatalf("packages.Load: want [command-line-arguments] or [missing.go], got %v", pkgs)
	}
	if len(pkgs[0].Errors) == 0 {
		t.Errorf("result of Load: want package with errors, got none: %+v", pkgs[0])
	}
}

func TestReturnErrorWhenUsingNonGoFiles(t *testing.T) {
	testAllOrModulesParallel(t, testReturnErrorWhenUsingNonGoFiles)
}
func testReturnErrorWhenUsingNonGoFiles(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/gopatha",
		Files: map[string]interface{}{
			"a/a.go": `package a`,
		}}, {
		Name: "golang.org/gopathb",
		Files: map[string]interface{}{
			"b/b.c": `package b`,
		}}})
	defer exported.Cleanup()
	config := packages.Config{Env: append(os.Environ(), "GOPACKAGESDRIVER=off")}
	pkgs, err := packages.Load(&config, "b/b.c")
	if err != nil {
		return
	}
	// Go <1.14 calls the package command-line-arguments while Go 1.14+ uses the file names.
	if len(pkgs) != 1 || (pkgs[0].PkgPath != "command-line-arguments" && pkgs[0].PkgPath != "b/b.c") {
		t.Fatalf("packages.Load: want [command-line-arguments] or [b/b.c], got %v", pkgs)
	}
	if len(pkgs[0].Errors) != 1 {
		t.Fatalf("result of Load: want package with one error, got: %+v", pkgs[0])
	}
}

func TestReturnErrorWhenUsingGoFilesInMultipleDirectories(t *testing.T) {
	testAllOrModulesParallel(t, testReturnErrorWhenUsingGoFilesInMultipleDirectories)
}
func testReturnErrorWhenUsingGoFilesInMultipleDirectories(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/gopatha",
		Files: map[string]interface{}{
			"a/a.go": `package a`,
			"b/b.go": `package b`,
		}}})
	defer exported.Cleanup()
	want := "named files must all be in one directory"
	pkgs, err := packages.Load(exported.Config, exported.File("golang.org/gopatha", "a/a.go"), exported.File("golang.org/gopatha", "b/b.go"))
	if err != nil {
		// Check if the error returned is the one we expected.
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("want error message: %s, got: %s", want, err.Error())
		}
		return
	}
	if len(pkgs) != 1 || pkgs[0].PkgPath != "command-line-arguments" {
		t.Fatalf("packages.Load: want [command-line-arguments], got %v", pkgs)
	}
	if len(pkgs[0].Errors) != 1 {
		t.Fatalf("result of Load: want package with one error, got: %+v", pkgs[0])
	}
	got := pkgs[0].Errors[0].Error()
	if !strings.Contains(got, want) {
		t.Fatalf("want error message: %s, got: %s", want, got)
	}
}

func TestReturnErrorForUnexpectedDirectoryLayout(t *testing.T) {
	testAllOrModulesParallel(t, testReturnErrorForUnexpectedDirectoryLayout)
}
func testReturnErrorForUnexpectedDirectoryLayout(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/gopatha",
		Files: map[string]interface{}{
			"a/testdata/a.go": `package a; import _ "b"`,
			"a/vendor/b/b.go": `package b; import _ "fmt"`,
		}}})
	defer exported.Cleanup()
	want := "unexpected directory layout"
	// triggering this error requires a relative package path
	exported.Config.Dir = filepath.Dir(exported.File("golang.org/gopatha", "a/testdata/a.go"))
	pkgs, err := packages.Load(exported.Config, ".")

	// This error doesn't seem to occur in module mode; so only
	// complain if we get zero packages while also getting no error.
	if err == nil {
		if len(pkgs) == 0 {
			// TODO(dh): we'll need to expand on the error check if/when Go stops emitting this error
			t.Fatalf("want error, got nil")
		}
		return
	}
	// Check if the error returned is the one we expected.
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("want error message: %s, got: %s", want, err.Error())
	}
}

func TestMissingDependency(t *testing.T) { testAllOrModulesParallel(t, testMissingDependency) }
func testMissingDependency(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import _ "this/package/doesnt/exist"`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.LoadAllSyntax
	pkgs, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 && pkgs[0].PkgPath != "golang.org/fake/a" {
		t.Fatalf("packages.Load: want [golang.org/fake/a], got %v", pkgs)
	}
	if len(pkgs[0].Errors) == 0 {
		t.Errorf("result of Load: want package with errors, got none: %+v", pkgs[0])
	}
}

func TestAdHocContains(t *testing.T) { testAllOrModulesParallel(t, testAdHocContains) }
func testAdHocContains(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a;`,
		}}})
	defer exported.Cleanup()

	tmpfile, err := ioutil.TempFile("", "adhoc*.go")
	filename := tmpfile.Name()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(tmpfile, `package main; import "fmt"; func main() { fmt.Println("time for coffee") }`)
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := os.Remove(filename); err != nil {
			t.Fatal(err)
		}
	}()

	exported.Config.Mode = packages.NeedImports | packages.NeedFiles
	pkgs, err := packages.Load(exported.Config, "file="+filename)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 && pkgs[0].PkgPath != "command-line-arguments" {
		t.Fatalf("packages.Load: want [command-line-arguments], got %v", pkgs)
	}
	pkg := pkgs[0]
	if _, ok := pkg.Imports["fmt"]; !ok || len(pkg.Imports) != 1 {
		t.Fatalf("Imports of loaded package: want [fmt], got %v", pkg.Imports)
	}
	if len(pkg.GoFiles) != 1 || pkg.GoFiles[0] != filename {
		t.Fatalf("GoFiles of loaded package: want [%s], got %v", filename, pkg.GoFiles)
	}
}

func TestCgoNoCcompiler(t *testing.T) { testAllOrModulesParallel(t, testCgoNoCcompiler) }
func testCgoNoCcompiler(t *testing.T, exporter packagestest.Exporter) {
	testenv.NeedsTool(t, "cgo")
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a
import "net/http"
const A = http.MethodGet
`,
		}}})
	defer exported.Cleanup()

	// Explicitly enable cgo but configure a nonexistent C compiler.
	exported.Config.Env = append(exported.Config.Env, "CGO_ENABLED=1", "CC=doesnotexist")
	exported.Config.Mode = packages.LoadAllSyntax
	initial, err := packages.Load(exported.Config, "golang.org/fake/a")

	if err != nil {
		t.Fatal(err)
	}

	// Check value of a.A.
	a := initial[0]
	aA := constant(a, "A")
	if aA == nil {
		t.Fatalf("a.A: got nil")
	}
	got := aA.Val().String()
	if got != "\"GET\"" {
		t.Errorf("a.A: got %s, want %s", got, "\"GET\"")
	}
}

func TestCgoMissingFile(t *testing.T) { testAllOrModulesParallel(t, testCgoMissingFile) }
func testCgoMissingFile(t *testing.T, exporter packagestest.Exporter) {
	testenv.NeedsTool(t, "cgo")
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a

// #include "foo.h"
import "C"

const A = 4
`,
		}}})
	defer exported.Cleanup()

	// Explicitly enable cgo.
	exported.Config.Env = append(exported.Config.Env, "CGO_ENABLED=1")
	exported.Config.Mode = packages.LoadAllSyntax
	initial, err := packages.Load(exported.Config, "golang.org/fake/a")

	if err != nil {
		t.Fatal(err)
	}

	// Check value of a.A.
	a := initial[0]
	aA := constant(a, "A")
	if aA == nil {
		t.Fatalf("a.A: got nil")
	}
	got := aA.Val().String()
	if got != "4" {
		t.Errorf("a.A: got %s, want %s", got, "4")
	}
}

func TestLoadImportsC(t *testing.T) {
	// This test checks that when a package depends on the
	// test variant of "syscall", "unsafe", or "runtime/cgo", that dependency
	// is not removed when those packages are added when it imports "C".
	//
	// For this test to work, the external test of syscall must have a dependency
	// on net, and net must import "syscall" and "C".
	if runtime.GOOS == "windows" {
		t.Skipf("skipping on windows; packages on windows do not satisfy conditions for test.")
	}
	if runtime.GOOS == "plan9" {
		// See https://golang.org/issue/27100.
		t.Skip(`skipping on plan9; for some reason "net [syscall.test]" is not loaded`)
	}
	t.Parallel()
	testenv.NeedsGoPackages(t)

	cfg := &packages.Config{
		Context: testCtx,
		Mode:    packages.LoadImports,
		Tests:   true,
	}
	initial, err := packages.Load(cfg, "syscall", "net")
	if err != nil {
		t.Fatalf("failed to load imports: %v", err)
	}

	_, all := importGraph(initial)

	for _, test := range []struct {
		pattern    string
		wantImport string // an import to check for
	}{
		{"net", "syscall:syscall"},
		{"net [syscall.test]", "syscall:syscall [syscall.test]"},
		{"syscall_test [syscall.test]", "net:net [syscall.test]"},
	} {
		// Test the import paths.
		pkg := all[test.pattern]
		if pkg == nil {
			t.Errorf("package %q not loaded", test.pattern)
			continue
		}
		if imports := strings.Join(imports(pkg), " "); !strings.Contains(imports, test.wantImport) {
			t.Errorf("package %q: got \n%s, \nwant to have %s", test.pattern, imports, test.wantImport)
		}
	}
}

func TestCgoNoSyntax(t *testing.T) {
	testAllOrModulesParallel(t, testCgoNoSyntax)
}
func testCgoNoSyntax(t *testing.T, exporter packagestest.Exporter) {
	testenv.NeedsTool(t, "cgo")

	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"c/c.go": `package c; import "C"`,
		},
	}})

	// Explicitly enable cgo.
	exported.Config.Env = append(exported.Config.Env, "CGO_ENABLED=1")

	modes := []packages.LoadMode{
		packages.NeedTypes,
		packages.NeedName | packages.NeedTypes,
		packages.NeedName | packages.NeedTypes | packages.NeedImports,
		packages.NeedName | packages.NeedTypes | packages.NeedImports | packages.NeedDeps,
		packages.NeedName | packages.NeedImports,
	}
	for _, mode := range modes {
		mode := mode
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			exported.Config.Mode = mode
			pkgs, err := packages.Load(exported.Config, "golang.org/fake/c")
			if err != nil {
				t.Fatal(err)
			}
			if len(pkgs) != 1 {
				t.Fatalf("Expected 1 package, got %v", pkgs)
			}
			pkg := pkgs[0]
			if len(pkg.Errors) != 0 {
				t.Fatalf("Expected no errors in package, got %v", pkg.Errors)
			}
		})
	}
}

func TestCgoBadPkgConfig(t *testing.T) {
	testAllOrModulesParallel(t, testCgoBadPkgConfig)
}
func testCgoBadPkgConfig(t *testing.T, exporter packagestest.Exporter) {
	skipIfShort(t, "builds and links a fake pkgconfig binary")
	testenv.NeedsTool(t, "cgo")

	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"c/c.go": `package c

// #cgo pkg-config: --cflags --  foo
import "C"`,
		},
	}})

	dir := buildFakePkgconfig(t, exported.Config.Env)
	defer os.RemoveAll(dir)
	env := exported.Config.Env
	for i, v := range env {
		if strings.HasPrefix(v, "PATH=") {
			env[i] = "PATH=" + dir + string(os.PathListSeparator) + v[len("PATH="):]
		}
	}

	exported.Config.Env = append(exported.Config.Env, "CGO_ENABLED=1")

	exported.Config.Mode = packages.NeedName | packages.NeedCompiledGoFiles
	pkgs, err := packages.Load(exported.Config, "golang.org/fake/c")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("Expected 1 package, got %v", pkgs)
	}
	if pkgs[0].Name != "c" {
		t.Fatalf("Expected package to have name \"c\", got %q", pkgs[0].Name)
	}
}

func buildFakePkgconfig(t *testing.T, env []string) string {
	tmpdir, err := ioutil.TempDir("", "fakepkgconfig")
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(filepath.Join(tmpdir, "pkg-config.go"), []byte(`
package main

import "fmt"
import "os"

func main() {
	fmt.Fprintln(os.Stderr, "bad")
	os.Exit(2)
}
`), 0644)
	if err != nil {
		os.RemoveAll(tmpdir)
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", "pkg-config", "pkg-config.go")
	cmd.Dir = tmpdir
	cmd.Env = env

	if b, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(tmpdir)
		fmt.Println(os.Environ())
		t.Log(string(b))
		t.Fatal(err)
	}
	return tmpdir
}

func TestIssue32814(t *testing.T) { testAllOrModulesParallel(t, testIssue32814) }
func testIssue32814(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name:  "golang.org/fake",
		Files: map[string]interface{}{}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.NeedName | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedTypesSizes
	pkgs, err := packages.Load(exported.Config, "fmt")

	if err != nil {
		t.Fatal(err)
	}

	if len(pkgs) != 1 && pkgs[0].PkgPath != "fmt" {
		t.Fatalf("packages.Load: want [fmt], got %v", pkgs)
	}
	pkg := pkgs[0]
	if len(pkg.Errors) != 0 {
		t.Fatalf("Errors for fmt pkg: got %v, want none", pkg.Errors)
	}
	if !pkg.Types.Complete() {
		t.Fatalf("Types.Complete() for fmt pkg: got %v, want true", pkgs[0].Types.Complete())

	}
}

func TestLoadTypesInfoWithoutNeedDeps(t *testing.T) {
	testAllOrModulesParallel(t, testLoadTypesInfoWithoutNeedDeps)
}
func testLoadTypesInfoWithoutNeedDeps(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import _ "golang.org/fake/b"`,
			"b/b.go": `package b`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports
	pkgs, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}
	pkg := pkgs[0]
	if pkg.IllTyped {
		t.Fatal("Loaded package is ill typed")
	}
	const expectedImport = "golang.org/fake/b"
	if _, ok := pkg.Imports[expectedImport]; !ok || len(pkg.Imports) != 1 {
		t.Fatalf("Imports of loaded package: want [%s], got %v", expectedImport, pkg.Imports)
	}
}

func TestLoadWithNeedDeps(t *testing.T) {
	testAllOrModulesParallel(t, testLoadWithNeedDeps)
}
func testLoadWithNeedDeps(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import _ "golang.org/fake/b"`,
			"b/b.go": `package b; import _ "golang.org/fake/c"`,
			"c/c.go": `package c`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps
	pkgs, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(pkgs))
	}

	pkgA := pkgs[0]
	if pkgA.IllTyped {
		t.Fatal("Loaded package is ill typed")
	}

	pkgB := pkgA.Imports["golang.org/fake/b"]
	if pkgB == nil || len(pkgA.Imports) != 1 {
		t.Fatalf("Imports of loaded package 'a' are invalid: %v", pkgA.Imports)
	}
	if pkgB.Types == nil || !pkgB.Types.Complete() || pkgB.TypesInfo == nil {
		t.Fatalf("Types of package 'b' are nil or incomplete: %v, %v", pkgB.Types, pkgB.TypesInfo)
	}

	pkgC := pkgB.Imports["golang.org/fake/c"]
	if pkgC == nil || len(pkgB.Imports) != 1 {
		t.Fatalf("Imports of loaded package 'c' are invalid: %v", pkgB.Imports)
	}
	if pkgC.Types == nil || !pkgC.Types.Complete() || pkgC.TypesInfo == nil {
		t.Fatalf("Types of package 'b' are nil or incomplete: %v, %v", pkgC.Types, pkgC.TypesInfo)
	}
}

func TestImpliedLoadMode(t *testing.T) {
	testAllOrModulesParallel(t, testImpliedLoadMode)
}
func testImpliedLoadMode(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import _ "golang.org/fake/b"`,
			"b/b.go": `package b`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.NeedTypes | packages.NeedTypesInfo
	pkgs, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(pkgs))
	}

	pkg := pkgs[0]
	if pkg.IllTyped {
		t.Fatalf("Loaded package is ill typed: %v", pkg.Errors)
	}

	// Check that packages.NeedTypesInfo worked well.
	if !pkg.Types.Complete() {
		t.Fatalf("Loaded package types are incomplete")
	}

	// Check that implied packages.NeedImports by packages.NeedTypesInfo
	// didn't add Imports.
	if len(pkg.Imports) != 0 {
		t.Fatalf("Package imports weren't requested but were returned: %v", pkg.Imports)
	}
}

func TestIssue35331(t *testing.T) {
	testAllOrModulesParallel(t, testIssue35331)
}
func testIssue35331(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
	}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedImports | packages.NeedDeps | packages.NeedSyntax
	exported.Config.Tests = false
	pkgs, err := packages.Load(exported.Config, "strconv")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("Expected 1 package, got %v", pkgs)
	}
	packages.Visit(pkgs, func(pkg *packages.Package) bool {
		if len(pkg.Errors) > 0 {
			t.Errorf("Expected no errors in package %q, got %v", pkg.ID, pkg.Errors)
		}
		if len(pkg.Syntax) == 0 && pkg.ID != "unsafe" {
			t.Errorf("Expected syntax on package %q, got none.", pkg.ID)
		}
		return true
	}, nil)
}

func TestMultiplePackageVersionsIssue36188(t *testing.T) {
	testAllOrModulesParallel(t, testMultiplePackageVersionsIssue36188)
}

func testMultiplePackageVersionsIssue36188(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import _ "golang.org/fake/b"`,
			"b/b.go": `package main`,
		}}})
	pkgs, err := packages.Load(exported.Config, "golang.org/fake/a", "golang.org/fake/b")
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].ID < pkgs[j].ID })
	if len(pkgs) != 2 {
		t.Fatalf("expected two packages, got %v", pkgs)
	}
	if pkgs[0].ID != "golang.org/fake/a" && pkgs[1].ID != "golang.org/fake/b" {
		t.Fatalf(`expected (sorted) IDs "golang.org/fake/a" and "golang.org/fake/b", got %q and %q`,
			pkgs[0].ID, pkgs[1].ID)
	}
	if pkgs[0].Errors == nil {
		t.Errorf(`expected error on package "golang.org/fake/a", got none`)
	}
	if pkgs[1].Errors != nil {
		t.Errorf(`expected no errors on package "golang.org/fake/b", got %v`, pkgs[1].Errors)
	}
	defer exported.Cleanup()
}

func TestLoadModeStrings(t *testing.T) {
	testcases := []struct {
		mode     packages.LoadMode
		expected string
	}{
		{
			packages.LoadMode(0),
			"LoadMode(0)",
		},
		{
			packages.NeedName,
			"LoadMode(NeedName)",
		},
		{
			packages.NeedFiles,
			"LoadMode(NeedFiles)",
		},
		{
			packages.NeedCompiledGoFiles,
			"LoadMode(NeedCompiledGoFiles)",
		},
		{
			packages.NeedImports,
			"LoadMode(NeedImports)",
		},
		{
			packages.NeedDeps,
			"LoadMode(NeedDeps)",
		},
		{
			packages.NeedExportsFile,
			"LoadMode(NeedExportsFile)",
		},
		{
			packages.NeedTypes,
			"LoadMode(NeedTypes)",
		},
		{
			packages.NeedSyntax,
			"LoadMode(NeedSyntax)",
		},
		{
			packages.NeedTypesInfo,
			"LoadMode(NeedTypesInfo)",
		},
		{
			packages.NeedTypesSizes,
			"LoadMode(NeedTypesSizes)",
		},
		{
			packages.NeedName | packages.NeedExportsFile,
			"LoadMode(NeedName|NeedExportsFile)",
		},
		{
			packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedExportsFile | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedTypesSizes,
			"LoadMode(NeedName|NeedFiles|NeedCompiledGoFiles|NeedImports|NeedDeps|NeedExportsFile|NeedTypes|NeedSyntax|NeedTypesInfo|NeedTypesSizes)",
		},
		{
			packages.NeedName | 8192,
			"LoadMode(NeedName|Unknown)",
		},
		{
			4096,
			"LoadMode(Unknown)",
		},
	}

	for tcInd, tc := range testcases {
		t.Run(fmt.Sprintf("test-%d", tcInd), func(t *testing.T) {
			actual := tc.mode.String()
			if tc.expected != actual {
				t.Errorf("want %#v, got %#v", tc.expected, actual)
			}
		})
	}
}

func TestCycleImportStack(t *testing.T) {
	testAllOrModulesParallel(t, testCycleImportStack)
}
func testCycleImportStack(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a; import _ "golang.org/fake/b"`,
			"b/b.go": `package b; import _ "golang.org/fake/a"`,
		}}})
	defer exported.Cleanup()

	exported.Config.Mode = packages.NeedName | packages.NeedImports
	pkgs, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("Expected 1 package, got %v", pkgs)
	}
	pkg := pkgs[0]
	if len(pkg.Errors) != 1 {
		t.Fatalf("Expected one error in package, got %v", pkg.Errors)
	}
	expected := "import cycle not allowed: import stack: [golang.org/fake/a golang.org/fake/b golang.org/fake/a]"
	if pkg.Errors[0].Msg != expected {
		t.Fatalf("Expected error %q, got %q", expected, pkg.Errors[0].Msg)
	}
}

func TestForTestField(t *testing.T) {
	testAllOrModulesParallel(t, testForTestField)
}
func testForTestField(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go":      `package a; func hello() {};`,
			"a/a_test.go": `package a; import "testing"; func TestA1(t *testing.T) {};`,
			"a/x_test.go": `package a_test; import "testing"; func TestA2(t *testing.T) {};`,
		}}})
	defer exported.Cleanup()

	// Add overlays to make sure they don't affect anything.
	exported.Config.Overlay = map[string][]byte{
		"a/a_test.go": []byte(`package a; import "testing"; func TestA1(t *testing.T) { hello(); };`),
		"a/x_test.go": []byte(`package a_test; import "testing"; func TestA2(t *testing.T) { hello(); };`),
	}
	exported.Config.Tests = true
	exported.Config.Mode = packages.NeedName | packages.NeedImports
	forTest := "golang.org/fake/a"
	pkgs, err := packages.Load(exported.Config, forTest)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 4 {
		t.Errorf("expected 4 packages, got %v", len(pkgs))
	}
	for _, pkg := range pkgs {
		var hasTestFile bool
		for _, f := range pkg.CompiledGoFiles {
			if strings.Contains(f, "a_test.go") || strings.Contains(f, "x_test.go") {
				hasTestFile = true
				break
			}
		}
		if !hasTestFile {
			continue
		}
		got := packagesinternal.GetForTest(pkg)
		if got != forTest {
			t.Errorf("expected %q, got %q", forTest, got)
		}
	}
}

func TestIssue37529(t *testing.T) {
	testAllOrModulesParallel(t, testIssue37529)
}
func testIssue37529(t *testing.T, exporter packagestest.Exporter) {
	// Tests #37529. When automatic vendoring is triggered, and we try to determine
	// the module root dir for a new overlay package, we previously would do a go list -m all,
	// which is incompatible with automatic vendoring.

	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"c/c2.go":             `package c`,
			"a/a.go":              `package a; import "b.com/b"; const A = b.B`,
			"vendor/b.com/b/b.go": `package b; const B = 4`,
		}}})
	rootDir := filepath.Dir(filepath.Dir(exported.File("golang.org/fake", "a/a.go")))
	exported.Config.Overlay = map[string][]byte{
		filepath.Join(rootDir, "c/c.go"): []byte(`package c; import "golang.org/fake/a"; const C = a.A`),
	}
	exported.Config.Env = append(exported.Config.Env, "GOFLAGS=-mod=vendor")
	exported.Config.Mode = packages.LoadAllSyntax

	defer exported.Cleanup()

	initial, err := packages.Load(exported.Config, "golang.org/fake/c")
	if err != nil {
		t.Fatal(err)
	}

	// Check value of a.A.
	a := initial[0]
	aA := constant(a, "C")
	if aA == nil {
		t.Fatalf("a.A: got nil")
	}
	got := aA.Val().String()
	if got != "4" {
		t.Errorf("a.A: got %s, want %s", got, "4")
	}
}

func TestIssue37098(t *testing.T) { testAllOrModulesParallel(t, testIssue37098) }
func testIssue37098(t *testing.T, exporter packagestest.Exporter) {
	// packages.Load should only return Go sources in
	// (*Package).CompiledGoFiles.  This tests #37098, where using SWIG to
	// causes C++ sources to be inadvertently included in
	// (*Package).CompiledGoFiles.

	// This is fixed in Go 1.17, but not earlier.
	testenv.NeedsGo1Point(t, 17)

	if _, err := exec.LookPath("swig"); err != nil {
		t.Skip("skipping test: swig not available")
	}
	if _, err := exec.LookPath("g++"); err != nil {
		t.Skip("skipping test: g++ not available")
	}

	// Create a fake package with an empty Go source, and a SWIG interface
	// file.
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			// The "package" statement must be included for SWIG sources to
			// be generated.
			"a/a.go":      "package a",
			"a/a.swigcxx": "",
		}}})
	defer exported.Cleanup()

	initial, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatalf("failed to load the package: %v", err)
	}
	// Try and parse each of the files
	for _, pkg := range initial {
		for _, file := range pkg.CompiledGoFiles {

			// Validate that each file can be parsed as a Go source.
			fset := token.NewFileSet()
			_, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
			if err != nil {
				t.Errorf("Failed to parse file '%s' as a Go source: %v", file, err)

				contents, err := ioutil.ReadFile(file)
				if err != nil {
					t.Fatalf("Failed to read the un-parsable file '%s': %v", file, err)
				}

				// Print out some of the un-parsable file to aid in debugging.
				n := len(contents)

				// Don't print the whole file if it is too large.
				const maxBytes = 1000
				if n > maxBytes {
					n = maxBytes
				}

				t.Logf("First %d bytes of un-parsable file: %s", n, contents[:n])
			}
		}
	}
}

// TestInvalidFilesInXTest checks the fix for golang/go#37971 in Go 1.15.
func TestInvalidFilesInXTest(t *testing.T) { testAllOrModulesParallel(t, testInvalidFilesInXTest) }
func testInvalidFilesInXTest(t *testing.T, exporter packagestest.Exporter) {
	testenv.NeedsGo1Point(t, 15)
	exported := packagestest.Export(t, exporter, []packagestest.Module{
		{
			Name: "golang.org/fake",
			Files: map[string]interface{}{
				"d/d.go":      `package d; import "net/http"; const d = http.MethodGet; func Get() string { return d; }`,
				"d/d2.go":     ``, // invalid file
				"d/d_test.go": `package d_test; import "testing"; import "golang.org/fake/d"; func TestD(t *testing.T) { d.Get(); }`,
			},
		},
	})
	defer exported.Cleanup()

	exported.Config.Mode = packages.NeedName | packages.NeedFiles
	exported.Config.Tests = true

	initial, err := packages.Load(exported.Config, "golang.org/fake/d")
	if err != nil {
		t.Fatal(err)
	}
	if len(initial) != 3 {
		t.Errorf("expected 3 packages, got %d", len(initial))
	}
}

func TestTypecheckCgo(t *testing.T) { testAllOrModulesParallel(t, testTypecheckCgo) }
func testTypecheckCgo(t *testing.T, exporter packagestest.Exporter) {
	testenv.NeedsGo1Point(t, 15)
	testenv.NeedsTool(t, "cgo")

	const cgo = `package cgo
		import "C"

		func Example() {
			C.CString("hi")
		}
	`
	exported := packagestest.Export(t, exporter, []packagestest.Module{
		{
			Name: "golang.org/fake",
			Files: map[string]interface{}{
				"cgo/cgo.go": cgo,
			},
		},
	})
	defer exported.Cleanup()

	exported.Config.Mode = packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedSyntax | packages.NeedDeps | packages.NeedTypes |
		packages.LoadMode(packagesinternal.TypecheckCgo)

	initial, err := packages.Load(exported.Config, "golang.org/fake/cgo")
	if err != nil {
		t.Fatal(err)
	}
	pkg := initial[0]
	if len(pkg.Errors) != 0 {
		t.Fatalf("package has errors: %v", pkg.Errors)
	}

	expos := pkg.Types.Scope().Lookup("Example").Pos()
	fname := pkg.Fset.File(expos).Name()
	if !strings.HasSuffix(fname, "cgo.go") {
		t.Errorf("position for cgo package was loaded from %v, wanted cgo.go", fname)
	}
}

func TestModule(t *testing.T) {
	testAllOrModulesParallel(t, testModule)
}
func testModule(t *testing.T, exporter packagestest.Exporter) {
	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name:  "golang.org/fake",
		Files: map[string]interface{}{"a/a.go": `package a`}}})
	exported.Config.Mode = packages.NeedModule
	rootDir := filepath.Dir(filepath.Dir(exported.File("golang.org/fake", "a/a.go")))

	initial, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}

	if len(initial) != 1 {
		t.Fatal("want exactly one package, got ", initial)
	}
	a := initial[0]
	switch exported.Exporter.Name() {
	case "GOPATH":
		if a.Module != nil {
			t.Fatal("package.Module: want nil, got ", a.Module)
		}
	case "Modules":
		// Make sure Modules field is set, and spot check a few of its fields.
		if a.Module == nil {
			t.Fatal("package.Module: want non-nil, got nil")
		}
		if a.Module.Path != "golang.org/fake" {
			t.Fatalf("package.Modile.Path: want \"golang.org/fake\", got %q", a.Module.Path)
		}
		if a.Module.GoMod != filepath.Join(rootDir, "go.mod") {
			t.Fatalf("package.Module.GoMod: want %q, got %q", filepath.Join(rootDir, "go.mod"), a.Module.GoMod)
		}
	default:
		t.Fatalf("Expected exporter to be GOPATH or Modules, got %v", exported.Exporter.Name())
	}
}

func TestExternal_NotHandled(t *testing.T) {
	testAllOrModulesParallel(t, testExternal_NotHandled)
}
func testExternal_NotHandled(t *testing.T, exporter packagestest.Exporter) {
	skipIfShort(t, "builds and links fake driver binaries")
	testenv.NeedsGoBuild(t)

	tempdir, err := ioutil.TempDir("", "testexternal")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempdir)

	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"a/a.go": `package a`,
			"empty_driver/main.go": `package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	ioutil.ReadAll(os.Stdin)
	fmt.Println("{}")
}
`,
			"nothandled_driver/main.go": `package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	ioutil.ReadAll(os.Stdin)
	fmt.Println("{\"NotHandled\": true}")
}
`,
		}}})
	baseEnv := exported.Config.Env

	// As a control, create a fake driver that always returns an empty response.
	emptyDriverPath := filepath.Join(tempdir, "empty_driver.exe") // Add .exe because Windows expects it.
	cmd := exec.Command("go", "build", "-o", emptyDriverPath, "golang.org/fake/empty_driver")
	cmd.Env = baseEnv
	cmd.Dir = exported.Config.Dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Log(string(b))
		t.Fatal(err)
	}

	exported.Config.Env = append(append([]string{}, baseEnv...), "GOPACKAGESDRIVER="+emptyDriverPath)
	initial, err := packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}

	if len(initial) != 0 {
		t.Errorf("package.Load with empty driver: want [], got %v", initial)
	}

	// Create a fake driver that always returns a NotHandled response.
	notHandledDriverPath := filepath.Join(tempdir, "nothandled_driver.exe")
	cmd = exec.Command("go", "build", "-o", notHandledDriverPath, "golang.org/fake/nothandled_driver")
	cmd.Env = baseEnv
	cmd.Dir = exported.Config.Dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Log(string(b))
		t.Fatal(err)
	}

	exported.Config.Env = append(append([]string{}, baseEnv...), "GOPACKAGESDRIVER="+notHandledDriverPath)
	initial, err = packages.Load(exported.Config, "golang.org/fake/a")
	if err != nil {
		t.Fatal(err)
	}

	if len(initial) != 1 || initial[0].PkgPath != "golang.org/fake/a" {
		t.Errorf("package.Load: want [golang.org/fake/a], got %v", initial)
	}
}

func TestInvalidPackageName(t *testing.T) {
	testAllOrModulesParallel(t, testInvalidPackageName)
}

func testInvalidPackageName(t *testing.T, exporter packagestest.Exporter) {
	testenv.NeedsGo1Point(t, 15)

	exported := packagestest.Export(t, exporter, []packagestest.Module{{
		Name: "golang.org/fake",
		Files: map[string]interface{}{
			"main.go": `package default

func main() {
}
`,
		},
	}})
	defer exported.Cleanup()

	initial, err := packages.Load(exported.Config, "golang.org/fake")
	if err != nil {
		t.Fatal(err)
	}
	pkg := initial[0]
	if len(pkg.CompiledGoFiles) != 1 {
		t.Fatalf("expected 1 Go file in package %s, got %v", pkg.ID, len(pkg.CompiledGoFiles))
	}
}

func TestEmptyEnvironment(t *testing.T) {
	t.Parallel()

	cfg := &packages.Config{
		Env: []string{"FOO=BAR"},
	}
	_, err := packages.Load(cfg, "fmt")
	if err == nil {
		t.Fatal("Load with explicitly empty environment should fail")
	}
}

func errorMessages(errors []packages.Error) []string {
	var msgs []string
	for _, err := range errors {
		msgs = append(msgs, err.Msg)
	}
	return msgs
}

func srcs(p *packages.Package) []string {
	return cleanPaths(append(p.GoFiles[:len(p.GoFiles):len(p.GoFiles)], p.OtherFiles...))
}

// cleanPaths attempts to reduce path names to stable forms
func cleanPaths(paths []string) []string {
	result := make([]string, len(paths))
	for i, src := range paths {
		// If the source file doesn't have an extension like .go or .s,
		// it comes from GOCACHE. The names there aren't predictable.
		name := filepath.Base(src)
		if !strings.Contains(name, ".") {
			result[i] = fmt.Sprintf("%d.go", i) // make cache names predictable
		} else {
			result[i] = name
		}
	}
	return result
}

// importGraph returns the import graph as a user-friendly string,
// and a map containing all packages keyed by ID.
func importGraph(initial []*packages.Package) (string, map[string]*packages.Package) {
	out := new(bytes.Buffer)

	initialSet := make(map[*packages.Package]bool)
	for _, p := range initial {
		initialSet[p] = true
	}

	// We can't use Visit because we need to prune
	// the traversal of specific edges, not just nodes.
	var nodes, edges []string
	res := make(map[string]*packages.Package)
	seen := make(map[*packages.Package]bool)
	var visit func(p *packages.Package)
	visit = func(p *packages.Package) {
		if !seen[p] {
			seen[p] = true
			if res[p.ID] != nil {
				panic("duplicate ID: " + p.ID)
			}
			res[p.ID] = p

			star := ' ' // mark initial packages with a star
			if initialSet[p] {
				star = '*'
			}
			nodes = append(nodes, fmt.Sprintf("%c %s", star, p.ID))

			// To avoid a lot of noise,
			// we prune uninteresting dependencies of testmain packages,
			// which we identify by this import:
			isTestMain := p.Imports["testing/internal/testdeps"] != nil

			for _, imp := range p.Imports {
				if isTestMain {
					switch imp.ID {
					case "os", "reflect", "testing", "testing/internal/testdeps":
						continue
					}
				}
				// math/bits took on a dependency on unsafe in 1.12, which breaks some
				// tests. As a short term hack, prune that edge.
				// ditto for ("errors", "internal/reflectlite") in 1.13.
				// TODO(matloob): think of a cleaner solution, or remove math/bits from the test.
				if p.ID == "math/bits" && imp.ID == "unsafe" {
					continue
				}
				edges = append(edges, fmt.Sprintf("%s -> %s", p, imp))
				visit(imp)
			}
		}
	}
	for _, p := range initial {
		visit(p)
	}

	// Sort, ignoring leading optional star prefix.
	sort.Slice(nodes, func(i, j int) bool { return nodes[i][2:] < nodes[j][2:] })
	for _, node := range nodes {
		fmt.Fprintf(out, "%s\n", node)
	}

	sort.Strings(edges)
	for _, edge := range edges {
		fmt.Fprintf(out, "  %s\n", edge)
	}

	return out.String(), res
}

func constant(p *packages.Package, name string) *types.Const {
	if p == nil || p.Types == nil {
		return nil
	}
	c := p.Types.Scope().Lookup(name)
	if c == nil {
		return nil
	}
	return c.(*types.Const)
}

func copyAll(srcPath, dstPath string) error {
	return filepath.Walk(srcPath, func(path string, info os.FileInfo, _ error) error {
		if info.IsDir() {
			return nil
		}
		contents, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcPath, path)
		if err != nil {
			return err
		}
		dstFilePath := strings.Replace(filepath.Join(dstPath, rel), "definitelynot_go.mod", "go.mod", -1)
		if err := os.MkdirAll(filepath.Dir(dstFilePath), 0755); err != nil {
			return err
		}
		if err := ioutil.WriteFile(dstFilePath, contents, 0644); err != nil {
			return err
		}
		return nil
	})
}
