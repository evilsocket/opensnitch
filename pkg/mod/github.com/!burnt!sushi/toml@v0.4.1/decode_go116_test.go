// +build go1.16

package toml

import (
	"fmt"
	"testing"
	"testing/fstest"
)

func TestDecodeFS(t *testing.T) {
	fsys := fstest.MapFS{
		"test.toml": &fstest.MapFile{
			Data: []byte("a = 42"),
		},
	}

	var i struct{ A int }
	meta, err := DecodeFS(fsys, "test.toml", &i)
	if err != nil {
		t.Fatal(err)
	}
	have := fmt.Sprintf("%v %v %v", i, meta.Keys(), meta.Type("a"))
	want := "{42} [a] Integer"
	if have != want {
		t.Errorf("\nhave: %s\nwant: %s", have, want)
	}
}
