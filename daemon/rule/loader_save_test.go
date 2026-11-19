package rule

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Save must replace the rule file atomically: after a successful Save the
// file is complete and parseable, has mode 0600 and no temporary file is
// left behind in the rules directory.
func TestLoaderSaveIsAtomic(t *testing.T) {
	// own directory: the package's shared tmpDir is watched by the
	// live-reload test and must not see our files
	dir := t.TempDir()
	var err error

	var list []Operator
	oper, _ := NewOperator(Simple, false, OpTrue, "", list)
	if err := oper.Compile(); err != nil {
		t.Fatal(err)
	}
	r := Create("000-save-atomic", "atomic save test", true, false, false, Allow, Always, oper)

	l, err := NewLoader(false)
	if err != nil {
		t.Fatal("NewLoader: ", err)
	}

	path := filepath.Join(dir, r.Name+".json")
	if err := l.Save(r, path); err != nil {
		t.Fatalf("Save() #1: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// a hard link keeps the first file's inode reachable: an in-place
	// rewrite would change what it reads, a rename leaves it untouched
	link := filepath.Join(dir, "first-save")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}

	// the second call must replace the existing file with a new one
	r.Description = "atomic save test, second save"
	if err := l.Save(r, path); err != nil {
		t.Fatalf("Save() #2: %v", err)
	}

	old, err := os.ReadFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, first) {
		t.Errorf("the first file was rewritten in place:\n got %s\nwant %s", old, first)
	}
	linkSt, err := os.Stat(link)
	if err != nil {
		t.Fatal(err)
	}
	pathSt, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(linkSt, pathSt) {
		t.Error("Save() reused the inode of the existing rule file instead of renaming a new file over it")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, first) {
		t.Error("the second Save() did not update the rule file")
	}
	var saved Rule
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("saved rule is not valid JSON: %v (%d bytes)", err, len(raw))
	}
	if saved.Name != r.Name || saved.Description != r.Description || saved.Action != Allow || saved.Duration != Always {
		t.Errorf("saved rule differs: name=%q description=%q action=%q duration=%q", saved.Name, saved.Description, saved.Action, saved.Duration)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", st.Mode().Perm())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected only %s in the rules dir, found %v", filepath.Base(path), names)
	}
}

// Saving into a directory that does not exist must fail cleanly without
// leaving anything behind.
func TestLoaderSaveMissingDir(t *testing.T) {
	var list []Operator
	oper, _ := NewOperator(Simple, false, OpTrue, "", list)
	r := Create("000-save-nodir", "atomic save test", true, false, false, Allow, Always, oper)
	l, _ := NewLoader(false)
	if err := l.Save(r, filepath.Join(t.TempDir(), "does-not-exist", "x.json")); err == nil {
		t.Error("Save() into a missing directory should fail")
	}
}
