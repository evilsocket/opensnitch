package ksym

import (
	"strings"
	"testing"
)

func TestKsym(t *testing.T) {
	data := "ffffffff91b2a340 T cgroup_freezing"

	r := strings.NewReader(data)
	fn := ksym("ffffffff91b2a340", r)

	if fn != "cgroup_freezing" {
		t.Error("unexpected result")
	}
}
