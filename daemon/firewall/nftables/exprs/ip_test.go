package exprs_test

import (
	"bytes"
	"net"
	"reflect"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestExprIP(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	type ipTestsT struct {
		name             string
		family           string
		values           []*config.ExprValues
		expectedExprsNum int
		expectedExprs    []interface{}
		expectedFail     bool
	}

	tests := []ipTestsT{
		{
			"test-ip-daddr",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "daddr",
					Value: "1.1.1.1",
				},
			},
			2,
			[]interface{}{
				&expr.Payload{
					SourceRegister: 0,
					DestRegister:   1,
					Offset:         16,
					Base:           expr.PayloadBaseNetworkHeader,
					Len:            4,
				},
				&expr.Cmp{
					Data: net.ParseIP("1.1.1.1").To4(),
				},
			},
			false,
		},
		{
			"test-ip-saddr",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "saddr",
					Value: "1.1.1.1",
				},
			},
			2,
			[]interface{}{
				&expr.Payload{
					SourceRegister: 1,
					DestRegister:   1,
					Offset:         12,
					Base:           expr.PayloadBaseNetworkHeader,
					Len:            4,
				},
				&expr.Cmp{
					Data: net.ParseIP("1.1.1.1").To4(),
				},
			},
			false,
		},
		{
			"test-inet-daddr",
			exprs.NFT_FAMILY_INET,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "daddr",
					Value: "1.1.1.1",
				},
			},
			4,
			[]interface{}{
				&expr.Meta{
					Key: expr.MetaKeyNFPROTO, Register: 1,
				},
				&expr.Cmp{
					Data: []byte{unix.NFPROTO_IPV4},
				},
				&expr.Payload{
					SourceRegister: 0,
					DestRegister:   1,
					Offset:         16,
					Base:           expr.PayloadBaseNetworkHeader,
					Len:            4,
				},
				&expr.Cmp{
					Data: net.ParseIP("1.1.1.1").To4(),
				},
			},
			false,
		},
		{
			"test-ip-daddr-invalid",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "daddr",
					Value: "1.1.1",
				},
			},
			0,
			[]interface{}{},
			true,
		},
		{
			"test-ip-daddr-invalid",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "daddr",
					Value: "1..1.1.1",
				},
			},
			0,
			[]interface{}{},
			true,
		},
		{
			"test-ip-daddr-invalid",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "daddr",
					Value: "www.test.com",
				},
			},
			0,
			[]interface{}{},
			true,
		},
		{
			"test-ip-daddr-invalid",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "daddr",
					Value: "",
				},
			},
			0,
			[]interface{}{},
			true,
		},
		{
			"test-inet-saddr",
			exprs.NFT_FAMILY_INET,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "saddr",
					Value: "1.1.1.1",
				},
			},
			4,
			[]interface{}{
				&expr.Meta{
					Key: expr.MetaKeyNFPROTO, Register: 1,
				},
				&expr.Cmp{
					Data: []byte{unix.NFPROTO_IPV4},
				},
				&expr.Payload{
					SourceRegister: 1,
					DestRegister:   1,
					Offset:         12,
					Base:           expr.PayloadBaseNetworkHeader,
					Len:            4,
				},
				&expr.Cmp{
					Data: net.ParseIP("1.1.1.1").To4(),
				},
			},
			false,
		},
		{
			"test-inet-daddr-invalid",
			exprs.NFT_FAMILY_INET,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "daddr",
					Value: "1..1.1.1",
				},
			},
			0,
			[]interface{}{},
			true,
		},
		{
			"test-inet-saddr-invalid",
			exprs.NFT_FAMILY_INET,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "saddr",
					Value: "1..1.1.1",
				},
			},
			0,
			[]interface{}{},
			true,
		},
		{
			"test-inet-range-daddr",
			exprs.NFT_FAMILY_INET,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "daddr",
					Value: "1.1.1.1-2.2.2.2",
				},
			},
			4,
			[]interface{}{
				&expr.Meta{
					Key: expr.MetaKeyNFPROTO, Register: 1,
				},
				&expr.Cmp{
					Data: []byte{unix.NFPROTO_IPV4},
				},
				&expr.Payload{
					SourceRegister: 0,
					DestRegister:   1,
					Offset:         16,
					Base:           expr.PayloadBaseNetworkHeader,
					Len:            4,
				},
				&expr.Range{
					Register: 1,
					FromData: net.ParseIP("1.1.1.1").To4(),
					ToData:   net.ParseIP("2.2.2.2").To4(),
				},
			},
			false,
		},
		{
			"test-inet-range-saddr",
			exprs.NFT_FAMILY_INET,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "saddr",
					Value: "1.1.1.1-2.2.2.2",
				},
			},
			4,
			[]interface{}{
				&expr.Meta{
					Key: expr.MetaKeyNFPROTO, Register: 1,
				},
				&expr.Cmp{
					Data: []byte{unix.NFPROTO_IPV4},
				},
				&expr.Payload{
					SourceRegister: 1,
					DestRegister:   1,
					Offset:         12,
					Base:           expr.PayloadBaseNetworkHeader,
					Len:            4,
				},
				&expr.Range{
					Register: 1,
					FromData: net.ParseIP("1.1.1.1").To4(),
					ToData:   net.ParseIP("2.2.2.2").To4(),
				},
			},
			false,
		},
		{
			"test-inet-daddr-range-invalid",
			exprs.NFT_FAMILY_INET,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "daddr",
					Value: "1.1.1.1--2.2.2.2",
				},
			},
			0,
			[]interface{}{},
			true,
		},
		{
			"test-inet-daddr-range-invalid",
			exprs.NFT_FAMILY_INET,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "daddr",
					Value: "1.1.1.1-1..2.2.2",
				},
			},
			0,
			[]interface{}{},
			true,
		},
		{
			"test-inet-daddr-range-invalid",
			exprs.NFT_FAMILY_INET,
			[]*config.ExprValues{
				&config.ExprValues{
					Key: "daddr",
					// TODO: not supported yet
					Value: "1.1.1.1/24",
				},
			},
			0,
			[]interface{}{},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ipExpr, err := exprs.NewExprIP(test.family, test.values, expr.CmpOpEq)
			if err != nil && !test.expectedFail {
				t.Errorf("Error creating expr IP: %s", ipExpr)
				return
			} else if err != nil && test.expectedFail {
				return
			}

			r, _ := nftest.AddTestRule(t, conn, ipExpr)
			if r == nil && !test.expectedFail {
				t.Error("Error adding rule with IP expression")
			}
			if total := len(r.Exprs); total != test.expectedExprsNum {
				t.Errorf("expected %d expressions, found %d", test.expectedExprsNum, total)
				return
			}

			for idx, e := range r.Exprs {
				if reflect.TypeOf(e).String() != reflect.TypeOf(test.expectedExprs[idx]).String() {
					t.Errorf("first expression should be %s, instead of: %s", reflect.TypeOf(test.expectedExprs[idx]), reflect.TypeOf(e))
					return
				}

				switch e.(type) {
				case *expr.Meta:
					lExpr, ok := e.(*expr.Meta)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Meta)
					if !ok || !okExpected {
						t.Errorf("invalid IP Meta expr: %+v, %+v", lExpr, lExpect)
						return
					}
					if lExpr.Key != lExpect.Key || lExpr.Register != lExpect.Register {
						t.Errorf("invalid Meta.Key. Returned: %+v\nExpected: %+v\n", lExpr.Key, lExpect.Key)
					}

				case *expr.Payload:
					lExpr, ok := e.(*expr.Payload)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Payload)
					if !ok || !okExpected {
						t.Errorf("invalid IP Payload expr: %+v, %+v", lExpr, lExpect)
						return
					}
					if lExpr.SourceRegister != lExpect.SourceRegister || lExpr.DestRegister != lExpect.DestRegister || lExpr.Offset != lExpect.Offset || lExpr.Base != lExpect.Base || lExpr.Len != lExpect.Len {
						t.Errorf("invalid IP Payload:\nReturned: %+v\nExpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Range:
				case *expr.Cmp:
					lExpr, ok := e.(*expr.Cmp)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Cmp)
					if !ok || !okExpected {
						t.Errorf("invalid Cmp expr: %+v, %+v", lExpr, lExpect)
						return
					}
					if !bytes.Equal(lExpr.Data, lExpect.Data) && !test.expectedFail {
						t.Errorf("invalid Cmp.Data: %+v, %+v", lExpr.Data, lExpect.Data)
						return
					}

				}

			}

			if test.expectedFail {
				t.Errorf("test should have failed")
			}
		})
	}

}
