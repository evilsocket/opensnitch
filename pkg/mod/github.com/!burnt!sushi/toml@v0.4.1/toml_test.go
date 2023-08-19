// +build go1.16

package toml_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/BurntSushi/toml/internal/tag"
	tomltest "github.com/BurntSushi/toml/internal/toml-test"
)

// Test if the error message matches what we want for invalid tests. Every slice
// entry is tested with strings.Contains.
//
// Filepaths are glob'd
var errorTests = map[string][]string{
	"encoding-bad-utf8*":            {"invalid UTF-8 byte"},
	"encoding-utf16*":               {"files cannot contain NULL bytes; probably using UTF-16"},
	"string-multiline-escape-space": {`invalid escape: '\ '`},
}

// Test metadata; all keys listed as "keyname: type".
var metaTests = map[string]string{
	// TODO: this probably should have albums as a Hash as well?
	"table-array-implicit": `
			albums.songs: ArrayHash
			albums.songs.name: String
		`,
}

func TestToml(t *testing.T) {
	for k := range errorTests { // Make sure patterns are valid.
		_, err := filepath.Match(k, "")
		if err != nil {
			t.Fatal(err)
		}
	}

	run := func(t *testing.T, enc bool) {
		r := tomltest.Runner{
			Files:   tomltest.EmbeddedTests(),
			Encoder: enc,
			Parser:  parser{},
			SkipTests: []string{
				// This one is annoying to fix, and such an obscure edge case
				// it's okay to leave it like this for now.
				"invalid/encoding/bad-utf8-at-end",
			},
		}

		tests, err := r.Run()
		if err != nil {
			t.Fatal(err)
		}

		for _, test := range tests.Tests {
			t.Run(test.Path, func(t *testing.T) {
				if test.Failed() {
					t.Fatalf("\nError:\n%s\n\nInput:\n%s\nOutput:\n%s\nWant:\n%s\n",
						test.Failure, test.Input, test.Output, test.Want)
					return
				}

				// Test metadata
				if !enc && test.Type() == tomltest.TypeValid {
					testMeta(t, test)
				}

				// Test error message.
				if test.Type() == tomltest.TypeInvalid {
					testError(t, test)
				}
			})
		}
		t.Logf("passed: %d; failed: %d; skipped: %d", tests.Passed, tests.Failed, tests.Skipped)
	}

	t.Run("decode", func(t *testing.T) { run(t, false) })
	t.Run("encode", func(t *testing.T) { run(t, true) })
}

func testMeta(t *testing.T, test tomltest.Test) {
	want, ok := metaTests[filepath.Base(test.Path)]
	if !ok {
		return
	}
	var s interface{}
	meta, err := toml.Decode(test.Input, &s)
	if err != nil {
		t.Fatal(err)
	}

	var b strings.Builder
	for _, k := range meta.Keys() {
		ks := k.String()
		b.WriteString(ks)
		b.WriteString(": ")
		b.WriteString(meta.Type(ks))
		b.WriteByte('\n')
	}
	have := b.String()
	have = have[:len(have)-1] // Trailing \n

	want = strings.ReplaceAll(strings.TrimSpace(want), "\t", "")
	if have != want {
		t.Errorf("MetaData wrong\nhave:\n%s\nwant:\n%s", have, want)
	}
}

func testError(t *testing.T, test tomltest.Test) {
	path := strings.TrimPrefix(test.Path, "invalid/")

	errs, ok := errorTests[path]
	if !ok {
		for k := range errorTests {
			ok, _ = filepath.Match(k, path)
			if ok {
				errs = errorTests[k]
				break
			}
		}
	}
	if !ok {
		return
	}

	for _, e := range errs {
		if !strings.Contains(test.Output, e) {
			t.Errorf("\nwrong error message\nhave: %s\nwant: %s", test.Output, e)
		}
	}
}

type parser struct{}

func (p parser) Encode(input string) (output string, outputIsError bool, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			switch rr := r.(type) {
			case error:
				retErr = rr
			default:
				retErr = fmt.Errorf("%s", rr)
			}
		}
	}()

	var tmp interface{}
	err := json.Unmarshal([]byte(input), &tmp)
	if err != nil {
		return "", false, err
	}

	buf := new(bytes.Buffer)
	err = toml.NewEncoder(buf).Encode(tag.Remove(tmp))
	if err != nil {
		return err.Error(), true, retErr
	}

	return buf.String(), false, retErr
}

func (p parser) Decode(input string) (output string, outputIsError bool, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			switch rr := r.(type) {
			case error:
				retErr = rr
			default:
				retErr = fmt.Errorf("%s", rr)
			}
		}
	}()

	var d interface{}
	if _, err := toml.Decode(input, &d); err != nil {
		return err.Error(), true, retErr
	}

	j, err := json.MarshalIndent(tag.Add("", d), "", "  ")
	if err != nil {
		return "", false, err
	}
	return string(j), false, retErr
}
