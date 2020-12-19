package rule

import "testing"

func TestCreate(t *testing.T) {
	t.Log("Test: Create rule")

	var list []Operator
	oper, _ := NewOperator(Simple, false, OpTrue, "", list)
	r := Create("000-test-name", true, false, Allow, Once, oper)
	t.Run("New rule must not be nil", func(t *testing.T) {
		if r == nil {
			t.Error("Create() returned nil")
			t.Fail()
		}
	})
	t.Run("Rule name must be 000-test-name", func(t *testing.T) {
		if r.Name != "000-test-name" {
			t.Error("Rule name error:", r.Name)
			t.Fail()
		}
	})
	t.Run("Rule must be enabled", func(t *testing.T) {
		if r.Enabled == false {
			t.Error("Rule Enabled is false:", r)
			t.Fail()
		}
	})
	t.Run("Rule Precedence must be false", func(t *testing.T) {
		if r.Precedence == true {
			t.Error("Rule Precedence is true:", r)
			t.Fail()
		}
	})
	t.Run("Rule Action must be Allow", func(t *testing.T) {
		if r.Action != Allow {
			t.Error("Rule Action is not Allow:", r.Action)
			t.Fail()
		}
	})
	t.Run("Rule Duration should be Once", func(t *testing.T) {
		if r.Duration != Once {
			t.Error("Rule Duration is not Once:", r.Duration)
			t.Fail()
		}
	})
}
