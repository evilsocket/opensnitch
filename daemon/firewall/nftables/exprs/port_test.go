package exprs_test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	exprs "github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

type portTestsT struct {
	port       string
	portVal    int
	cmp        expr.CmpOp
	shouldFail bool
}

func TestExprPort(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	portTests := []portTestsT{
		{"53", 53, expr.CmpOpEq, false},
		{"80", 80, expr.CmpOpEq, false},
		{"65535", 65535, expr.CmpOpEq, false},
		{"45,", 0, expr.CmpOpEq, true},
		{"", 0, expr.CmpOpEq, true},
	}

	for _, test := range portTests {
		t.Run(fmt.Sprint("test-", test.port), func(t *testing.T) {
			portExpr, err := exprs.NewExprPort(test.port, &test.cmp)
			if err != nil {
				if !test.shouldFail {
					t.Errorf("Error creating expr port: %v, %s", test, err)
				}
				return
			}
			//fmt.Printf("%s, %+v\n", test.port, *portExpr)
			r, _ := nftest.AddTestRule(t, conn, portExpr)
			if r == nil {
				t.Errorf("Error adding rule with port (%s) expression", test.port)
			}
			e := r.Exprs[0]
			cmp, ok := e.(*expr.Cmp)
			if !ok {
				t.Errorf("%s - invalid port expr: %T", test.port, e)
			}
			//fmt.Printf("%s, %+v\n", reflect.TypeOf(e).String(), e)
			if reflect.TypeOf(e).String() != "*expr.Cmp" {
				t.Errorf("%s - first expression should be *expr.Cmp, instead of: %s", test.port, reflect.TypeOf(e))
			}
			portVal := binaryutil.BigEndian.PutUint16(uint16(test.portVal))
			if !bytes.Equal(cmp.Data, portVal) {
				t.Errorf("%s - invalid port in expr.Cmp: %d", test.port, cmp.Data)
			}

		})
	}
}

func TestExprPortRange(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	portTests := []portTestsT{
		{"53-5353", 53, expr.CmpOpEq, false},
		{"80-8080", 80, expr.CmpOpEq, false},
		{"1-65535", 65535, expr.CmpOpEq, false},
		{"1,45,", 0, expr.CmpOpEq, true},
		{"1-2.", 0, expr.CmpOpEq, true},
	}

	for _, test := range portTests {
		t.Run(fmt.Sprint("test-", test.port), func(t *testing.T) {
			portExpr, err := exprs.NewExprPortRange(test.port, &test.cmp)
			if err != nil {
				if !test.shouldFail {
					t.Errorf("Error creating expr port range: %v, %s", test, err)
				}
				return
			}
			//fmt.Printf("%s, %+v\n", test.port, *portExpr)
			r, _ := nftest.AddTestRule(t, conn, portExpr)
			if r == nil {
				t.Errorf("Error adding rule with port range (%s) expression", test.port)
			}
			e := r.Exprs[0]
			_, ok := e.(*expr.Range)
			if !ok {
				t.Errorf("%s - invalid port range expr: %T", test.port, e)
			}
			fmt.Printf("%s, %+v\n", reflect.TypeOf(e).String(), e)
			if reflect.TypeOf(e).String() != "*expr.Range" {
				t.Errorf("%s - first expression should be *expr.Cmp, instead of: %s", test.port, reflect.TypeOf(e))
			}
			/*portVal := binaryutil.BigEndian.PutUint16(uint16(test.portVal))
			if !bytes.Equal(range.FromData, portVal) {
				t.Errorf("%s - invalid port range in expr.Cmp: %d", test.port, cmp.Data)
			}*/

		})
	}
}
