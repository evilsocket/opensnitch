// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildir_test

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
	"honnef.co/go/tools/internal/passes/buildir"
)

func Test(t *testing.T) {
	testdata := analysistest.TestData()
	result := analysistest.Run(t, testdata, buildir.Analyzer, "a")[0].Result

	irinfo := result.(*buildir.IR)
	got := fmt.Sprint(irinfo.SrcFuncs)
	want := `[a.init a.Fib (a.T).fib]`
	if got != want {
		t.Errorf("IR.SrcFuncs = %s, want %s", got, want)
		for _, f := range irinfo.SrcFuncs {
			f.WriteTo(os.Stderr)
		}
	}
}
