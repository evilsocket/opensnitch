package main

import (
	"testing"
)

type t1 struct{} // used_test

func TestFoo(t *testing.T) { // used_test
	_ = t1{}
}
