// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package a

import (
	"bytes"
	"fmt"
	"net/http"
)

type parent interface {
	n(f bool)
}

type yuh struct {
	a int
}

func (y *yuh) n(f bool) {
	for i := 0; i < 10; i++ {
		fmt.Println(i)
	}
}

func a(i1 int, i2 int, i3 int) int { // want "potentially unused parameter: 'i2'"
	i3 += i1
	_ = func(z int) int { // want "potentially unused parameter: 'z'"
		_ = 1
		return 1
	}
	return i3
}

func b(c bytes.Buffer) { // want "potentially unused parameter: 'c'"
	_ = 1
}

func z(h http.ResponseWriter, _ *http.Request) { // want "potentially unused parameter: 'h'"
	fmt.Println("Before")
}

func l(h http.Handler) http.Handler {
	return http.HandlerFunc(z)
}

func mult(a, b int) int { // want "potentially unused parameter: 'b'"
	a += 1
	return a
}

func y(a int) {
	panic("yo")
}
