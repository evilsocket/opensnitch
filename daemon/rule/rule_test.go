package rule

import (
	"testing"
)

func TestCreate(t *testing.T) {
	t.Log("Test: Create rule")

	var list []Operator
	oper, _ := NewOperator(Simple, false, OpTrue, "", list)
	r := Create("000-test-name", "rule description 000", true, false, false, Allow, Once, oper)
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

func TestRuleSerializers(t *testing.T) {
	t.Log("Test: Serializers()")

	var opList []Operator
	opList = append(opList, Operator{
		Type:    Simple,
		Operand: OpProcessPath,
		Data:    "/path/x",
	})
	opList = append(opList, Operator{
		Type:    Simple,
		Operand: OpDstPort,
		Data:    "23",
	})

	op, _ := NewOperator(List, false, OpTrue, "", opList)
	// this string must be erased after Deserialized
	op.Data = "[\"test\": true]"

	r := Create("000-test-serializer-list", "rule description 000", true, false, false, Allow, Once, op)

	rSerialized := r.Serialize()
	t.Run("Serialize() must not return nil", func(t *testing.T) {
		if rSerialized == nil {
			t.Error("rule.Serialize() returned nil")
			t.Fail()
		}
	})

	rDeser, err := Deserialize(rSerialized)
	t.Run("Deserialize must not return error", func(t *testing.T) {
		if err != nil {
			t.Error("rule.Serialize() returned error:", err)
			t.Fail()
		}
	})

	// commit: b93051026e6a82ba07a5ac2f072880e69f04c238
	t.Run("Deserialize. Operator.Data must be empty", func(t *testing.T) {
		if rDeser.Operator.Data != "" {
			t.Error("rule.Deserialize() Operator.Data not emptied:", rDeser.Operator.Data)
			t.Fail()
		}
	})

	t.Run("Deserialize. Operator.List must be expanded", func(t *testing.T) {
		if len(rDeser.Operator.List) != 2 {
			t.Error("rule.Deserialize() invalid Operator.List:", rDeser.Operator.List)
			t.Fail()
		}
		if rDeser.Operator.List[0].Operand != OpProcessPath {
			t.Error("rule.Deserialize() invalid Operator.List 1:", rDeser.Operator.List)
			t.Fail()
		}
		if rDeser.Operator.List[1].Operand != OpDstPort {
			t.Error("rule.Deserialize() invalid Operator.List 2:", rDeser.Operator.List)
			t.Fail()
		}
		if rDeser.Operator.List[0].Type != Simple || rDeser.Operator.List[1].Type != Simple {
			t.Error("rule.Deserialize() invalid Operator.List 3:", rDeser.Operator.List)
			t.Fail()
		}
		if rDeser.Operator.List[0].Data != "/path/x" || rDeser.Operator.List[1].Data != "23" {
			t.Error("rule.Deserialize() invalid Operator.List 4:", rDeser.Operator.List)
			t.Fail()
		}
	})

}
