//+build go1.8

package ir_test

import "testing"

func TestValueForExprStructConv(t *testing.T) {
	testValueForExpr(t, "testdata/structconv.go")
}
