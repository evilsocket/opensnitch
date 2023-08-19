package lintcmd

import (
	"go/token"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"honnef.co/go/tools/config"
	"honnef.co/go/tools/lintcmd/runner"

	"golang.org/x/tools/go/packages"
)

func testdata() string {
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		log.Fatal(err)
	}
	return testdata
}

func lintPackage(t *testing.T, name string) []problem {
	l, err := newLinter(config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &packages.Config{
		Env: append(os.Environ(), "GOPATH="+testdata(), "GO111MODULE=off"),
	}
	ps, _, err := l.Lint(cfg, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func trimPosition(pos *token.Position) {
	idx := strings.Index(pos.Filename, "/testdata/src/")
	if idx >= 0 {
		pos.Filename = pos.Filename[idx+len("/testdata/src/"):]
	}
}

func TestErrors(t *testing.T) {
	t.Run("invalid package declaration", func(t *testing.T) {
		ps := lintPackage(t, "broken_pkgerror")
		if len(ps) != 1 {
			t.Fatalf("got %d problems, want 1", len(ps))
		}
		if want := "expected 'package', found pckage"; ps[0].Message != want {
			t.Errorf("got message %q, want %q", ps[0].Message, want)
		}
		if ps[0].Position.Filename == "" {
			t.Errorf("didn't get useful position")
		}
	})

	t.Run("type error", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("don't deal with Windows line endings or absolute file names")
		}
		ps := lintPackage(t, "broken_typeerror")
		if len(ps) != 1 {
			t.Fatalf("got %d problems, want 1", len(ps))
		}
		trimPosition(&ps[0].Position)
		want := problem{
			Diagnostic: runner.Diagnostic{
				Position: token.Position{
					Filename: "broken_typeerror/pkg.go",
					Offset:   0,
					Line:     5,
					Column:   10,
				},
				Message:  "cannot convert \"\" (untyped string constant) to int",
				Category: "compile",
			},
			Severity: 0,
		}
		if !ps[0].equal(want) {
			t.Errorf("got %#v, want %#v", ps[0], want)
		}
	})

	t.Run("missing dep", func(t *testing.T) {
		t.Skip("Go 1.12 behaves incorrectly for missing packages")
	})

	t.Run("parse error", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("don't deal with Windows line endings or absolute file names")
		}
		ps := lintPackage(t, "broken_parse")
		if len(ps) != 1 {
			t.Fatalf("got %d problems, want 1", len(ps))
		}

		trimPosition(&ps[0].Position)
		want := problem{
			Diagnostic: runner.Diagnostic{
				Position: token.Position{
					Filename: "broken_parse/pkg.go",
					Offset:   0,
					Line:     3,
					Column:   1,
				},
				Message:  "expected declaration, found asd",
				Category: "compile",
			},
			Severity: 0,
		}
		if !ps[0].equal(want) {
			t.Errorf("got %#v, want %#v", ps[0], want)
		}
	})
}
