package exprs_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables/expr"
)

// https://github.com/evilsocket/opensnitch/blob/master/daemon/firewall/nftables/exprs/iface.go#L22
func ifname(n string) []byte {
	buf := make([]byte, 16)
	length := len(n)
	// allow wildcards
	if n[length-1:] == "*" {
		return []byte(n[:length-1])
	}
	copy(buf, []byte(n+"\x00"))
	return buf
}

func TestExprIface(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	type ifaceTestsT struct {
		name  string
		iface string
		out   bool
	}
	tests := []ifaceTestsT{
		{"test-in-iface-xxx", "in-iface0", false},
		{"test-out-iface-xxx", "out-iface0", true},
		{"test-out-iface-xxx-wildcard", "out-iface*", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ifaceExpr := exprs.NewExprIface(test.iface, test.out, expr.CmpOpEq)
			r, _ := nftest.AddTestRule(t, conn, ifaceExpr)
			if r == nil {
				t.Error("Error adding rule with iface expression")
			}
			if total := len(r.Exprs); total != 2 {
				t.Errorf("expected 2 expressions, got %d: %+v", total, r.Exprs)
			}
			e := r.Exprs[0]
			if reflect.TypeOf(e).String() != "*expr.Meta" {
				t.Errorf("first expression should be *expr.Meta, instead of: %s", reflect.TypeOf(e))
			}
			lExpr, ok := e.(*expr.Meta)
			if !ok {
				t.Errorf("invalid iface meta expr: %T", e)
			}
			if test.out && lExpr.Key != expr.MetaKeyOIFNAME {
				t.Errorf("iface Key should be MetaKeyOIFNAME instead of: %+v", lExpr)
			} else if !test.out && lExpr.Key != expr.MetaKeyIIFNAME {
				t.Errorf("iface Key should be MetaKeyIIFNAME instead of: %+v", lExpr)
			}

			e = r.Exprs[1]
			if reflect.TypeOf(e).String() != "*expr.Cmp" {
				t.Errorf("second expression should be *expr.Cmp, instead of: %s", reflect.TypeOf(e))
			}
			lCmp, ok := e.(*expr.Cmp)
			if !ok {
				t.Errorf("invalid iface cmp expr: %T", e)
			}
			if !bytes.Equal(lCmp.Data, ifname(test.iface)) {
				t.Errorf("iface Cmp does not match: %v, expected: %v", lCmp.Data, ifname(test.iface))
			}
		})
	}
}
