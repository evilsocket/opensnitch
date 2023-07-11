package nftest

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// TestsT defines the fields of a test.
type TestsT struct {
	Name             string
	Family           string
	Parms            string
	Values           []*config.ExprValues
	ExpectedExprsNum int
	ExpectedExprs    []interface{}
	ExpectedFail     bool
}

// AreExprsValid checks if the expressions defined in the given rule are valid
// according to the expected expressions defined in the tests.
func AreExprsValid(t *testing.T, test *TestsT, rule *nftables.Rule) bool {

	if total := len(rule.Exprs); total != test.ExpectedExprsNum {
		t.Errorf("expected %d expressions, found %d", test.ExpectedExprsNum, total)
		return false
	}

	for idx, e := range rule.Exprs {
		if reflect.TypeOf(e).String() != reflect.TypeOf(test.ExpectedExprs[idx]).String() {
			t.Errorf("first expression should be %s, instead of: %s", reflect.TypeOf(test.ExpectedExprs[idx]), reflect.TypeOf(e))
			return false
		}

		switch e.(type) {
		case *expr.Meta:
			lExpr, ok := e.(*expr.Meta)
			lExpect, okExpected := test.ExpectedExprs[idx].(*expr.Meta)
			if !ok || !okExpected {
				t.Errorf("invalid Meta expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}
			if lExpr.Key != lExpect.Key || lExpr.Register != lExpect.Register {
				t.Errorf("invalid Meta.Key,\ngot: %+v\nexpected: %+v\n", lExpr.Key, lExpect.Key)
			}
			if lExpr.SourceRegister != lExpect.SourceRegister {
				t.Errorf("invalid Meta.SourceRegister,\ngot: %+v\nexpected: %+v\n", lExpr.SourceRegister, lExpect.SourceRegister)
			}
			if lExpr.Register != lExpect.Register {
				t.Errorf("invalid Meta.Register,\ngot: %+v\nexpected: %+v\n", lExpr.SourceRegister, lExpect.SourceRegister)
			}

		case *expr.Immediate:
			lExpr, ok := e.(*expr.Immediate)
			lExpect, okExpected := test.ExpectedExprs[idx].(*expr.Immediate)
			if !ok || !okExpected {
				t.Errorf("invalid Immediate expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}
			if !bytes.Equal(lExpr.Data, lExpect.Data) && !test.ExpectedFail {
				t.Errorf("invalid Immediate.Data,\ngot: %+v,\nexpected: %+v", lExpr.Data, lExpect.Data)
				return false
			}

		case *expr.TProxy:
			lExpr, ok := e.(*expr.TProxy)
			lExpect, okExpected := test.ExpectedExprs[idx].(*expr.TProxy)
			if !ok || !okExpected {
				t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}
			if lExpr.Family != lExpect.Family || lExpr.TableFamily != lExpect.TableFamily || lExpr.RegPort != lExpect.RegPort {
				t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}

		case *expr.Redir:
			lExpr, ok := e.(*expr.Redir)
			lExpect, okExpected := test.ExpectedExprs[idx].(*expr.Redir)
			if !ok || !okExpected {
				t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}
			if lExpr.RegisterProtoMin != lExpect.RegisterProtoMin {
				t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}

		case *expr.Masq:
			lExpr, ok := e.(*expr.Masq)
			lExpect, okExpected := test.ExpectedExprs[idx].(*expr.Masq)
			if !ok || !okExpected {
				t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}
			if lExpr.ToPorts != lExpect.ToPorts ||
				lExpr.Random != lExpect.Random ||
				lExpr.FullyRandom != lExpect.FullyRandom ||
				lExpr.Persistent != lExpect.Persistent {
				t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}

		case *expr.NAT:
			lExpr, ok := e.(*expr.NAT)
			lExpect, okExpected := test.ExpectedExprs[idx].(*expr.NAT)
			if !ok || !okExpected {
				t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}
			if lExpr.RegProtoMin != lExpect.RegProtoMin ||
				lExpr.RegAddrMin != lExpect.RegAddrMin ||
				lExpr.Random != lExpect.Random ||
				lExpr.FullyRandom != lExpect.FullyRandom ||
				lExpr.Persistent != lExpect.Persistent {
				t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}

		case *expr.Quota:
			lExpr, ok := e.(*expr.Quota)
			lExpect, okExpected := test.ExpectedExprs[idx].(*expr.Quota)
			if !ok || !okExpected {
				t.Errorf("invalid Quota expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}
			if lExpr.Bytes != lExpect.Bytes ||
				lExpr.Over != lExpect.Over ||
				lExpr.Consumed != lExpect.Consumed {
				t.Errorf("invalid Quota.Data,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}

		case *expr.Cmp:
			lExpr, ok := e.(*expr.Cmp)
			lExpect, okExpected := test.ExpectedExprs[idx].(*expr.Cmp)
			if !ok || !okExpected {
				t.Errorf("invalid Cmp expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
				return false
			}
			if !bytes.Equal(lExpr.Data, lExpect.Data) && !test.ExpectedFail {
				t.Errorf("invalid Cmp.Data,\ngot: %+v,\nexpected: %+v", lExpr.Data, lExpect.Data)
				return false
			}
		}
	}

	return true
}
