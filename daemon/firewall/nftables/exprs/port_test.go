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
	proto      string
	direction  string
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
		{"udp", "dport", "53", 53, expr.CmpOpEq, false},
		{"tcp", "sport", "80", 80, expr.CmpOpEq, false},
		{"tcp", "dport", "65535", 65535, expr.CmpOpEq, false},
		{"udp", "sport", "45,", 0, expr.CmpOpEq, true},
		{"udp", "dport", "", 0, expr.CmpOpEq, true},
		{"udp", "dport", " ", 0, expr.CmpOpEq, true},
		{"udp", "dport", ".", 0, expr.CmpOpEq, true},
		{"udp", "dport", "a", 0, expr.CmpOpEq, true},
	}

	for _, test := range portTests {
		t.Run(fmt.Sprint("test-", test.port), func(t *testing.T) {
			exprProto, _ := exprs.NewExprProtocol(test.proto)
			exprPDir, _ := exprs.NewExprPortDirection(test.direction)
			portExpr, err := exprs.NewExprPort(test.port, &test.cmp)
			if err != nil {
				if !test.shouldFail {
					t.Errorf("Error creating expr port: %v, %s", test, err)
				}
				return
			}
			//fmt.Printf("%s, %+v\n", test.port, *portExpr)
			exprList := []expr.Any{}
			// expr.Meta
			exprList = append(exprList, *exprProto...)
			// expr.Payload
			exprList = append(exprList, []expr.Any{exprPDir}...)
			// expr.Cmp
			exprList = append(exprList, *portExpr...)
			r, _ := nftest.AddTestRule(t, conn, &exprList)
			if r == nil {
				t.Errorf("Error adding rule with port (%s) expression: %v", test.port, r)
				return
			}
			// meta[0] + cmp[1]
			e := r.Exprs[0]
			_, ok := e.(*expr.Meta)
			if !ok {
				t.Errorf("%s - invalid port expr meta: %T", test.port, e)
				return
			}

			// payload[2]
			e1 := r.Exprs[2]
			_, ok1 := e1.(*expr.Payload)
			if !ok1 {
				t.Errorf("%s - invalid port expr payload: %T", test.port, e1)
				return
			}

			// cmp[3] (port)
			e2 := r.Exprs[3]
			cmp, ok2 := e2.(*expr.Cmp)
			if !ok2 {
				t.Errorf("%s - invalid port expr cmp: %T", test.port, e2)
				return
			}
			//fmt.Printf("%s, %+v\n", reflect.TypeOf(e).String(), e)
			if reflect.TypeOf(e2).String() != "*expr.Cmp" {
				t.Errorf("%s - first expression should be *expr.Cmp, instead of: %s", test.port, reflect.TypeOf(e2))
				return
			}
			portVal := binaryutil.BigEndian.PutUint16(uint16(test.portVal))
			if !bytes.Equal(cmp.Data, portVal) {
				t.Errorf("%s - invalid port in expr.Cmp: %d", test.port, cmp.Data)
				return
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
		{"udp", "dport", "53-5353", 53, expr.CmpOpEq, false},
		{"tcp", "sport", "80-8080", 80, expr.CmpOpEq, false},
		{"udp", "dport", "1-65535", 65535, expr.CmpOpEq, false},
		{"tcp", "sport", "1,45,", 0, expr.CmpOpEq, true},
		{"udp", "dport", "1-2.", 0, expr.CmpOpEq, true},
		{"udp", "dport", "-2", 0, expr.CmpOpEq, true},
		{"udp", "dport", "-", 0, expr.CmpOpEq, true},
		{"udp", "dport", " ", 0, expr.CmpOpEq, true},
	}

	for _, test := range portTests {
		t.Run(fmt.Sprint("test-", test.port), func(t *testing.T) {
			exprProto, _ := exprs.NewExprProtocol(test.proto)
			exprPDir, _ := exprs.NewExprPortDirection(test.direction)
			portExpr, err := exprs.NewExprPortRange(test.port, &test.cmp)
			if err != nil {
				if !test.shouldFail {
					t.Errorf("Error creating expr port range: %v, %s", test, err)
				}
				return
			}
			fmt.Printf("%s, %+v\n", test.port, *portExpr)

			exprList := []expr.Any{}
			// expr.Meta
			exprList = append(exprList, *exprProto...)
			// expr.Payload
			exprList = append(exprList, []expr.Any{exprPDir}...)
			// expr.Range
			exprList = append(exprList, *portExpr...)

			r, _ := nftest.AddTestRule(t, conn, &exprList)
			if r == nil {
				t.Errorf("Error adding rule with port range (%s) expression", test.port)
				return
			}
			if len(r.Exprs) != 4 {
				t.Errorf("Error adding rule with port range (%s): expected 4 Exprs, found: %q", test.port, r.Exprs)
				return
			}
			// meta + cmp
			e := r.Exprs[0]
			_, ok := e.(*expr.Meta)
			if !ok {
				t.Errorf("%s - invalid port expr meta: %T, %q", test.port, e, r.Exprs)
				return
			}

			// payload
			e1 := r.Exprs[2]
			_, ok1 := e1.(*expr.Payload)
			if !ok1 {
				t.Errorf("%s - invalid port expr payload: %T, exprs: %q", test.port, e1, r.Exprs)
				return
			}
			e2 := r.Exprs[3]
			_, ok2 := e2.(*expr.Range)
			if !ok2 {
				t.Errorf("%s - invalid port range expr: %T, exprs: %q", test.port, 2, r.Exprs)
				return
			}
			//fmt.Printf("%s, %+v\n", reflect.TypeOf(e2).String(), e2)
			if reflect.TypeOf(e2).String() != "*expr.Range" {
				t.Errorf("%s - first expression should be *expr.Cmp, instead of: %s", test.port, reflect.TypeOf(e2))
			}
			/*portVal := binaryutil.BigEndian.PutUint16(uint16(test.portVal))
			if !bytes.Equal(range.FromData, portVal) {
				t.Errorf("%s - invalid port range in expr.Cmp: %d", test.port, cmp.Data)
			}*/

		})
	}
}
