package exprs_test

import (
	"fmt"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func TestExprCtMark(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	type ctTestsT struct {
		nftest.TestsT
		setMark bool
	}

	cmp := expr.CmpOpEq
	tests := []ctTestsT{
		{
			TestsT: nftest.TestsT{
				Name:             "test-ct-set-mark-666",
				Parms:            "666",
				ExpectedExprsNum: 2,
				ExpectedExprs: []interface{}{
					&expr.Immediate{
						Register: 1,
						Data:     binaryutil.NativeEndian.PutUint32(uint32(666)),
					},
					&expr.Ct{
						Key:            expr.CtKeyMARK,
						Register:       1,
						SourceRegister: true,
					},
				},
			},
			setMark: true,
		},
		{
			TestsT: nftest.TestsT{
				Name:             "test-ct-check-mark-666",
				Parms:            "666",
				ExpectedExprsNum: 3,
				ExpectedExprs: []interface{}{
					&expr.Immediate{
						Register: 1,
						Data:     binaryutil.NativeEndian.PutUint32(uint32(666)),
					},
					&expr.Ct{
						Key:            expr.CtKeyMARK,
						Register:       1,
						SourceRegister: false,
					},
					&expr.Cmp{
						Op:       cmp,
						Register: 1,
						Data:     binaryutil.NativeEndian.PutUint32(uint32(666)),
					},
				},
			},
			setMark: false,
		},
		{
			TestsT: nftest.TestsT{
				Name:             "test-invalid-ct-check-mark",
				Parms:            "0x29a",
				ExpectedExprsNum: 3,
				ExpectedExprs:    []interface{}{},
				ExpectedFail:     true,
			},
			setMark: false,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			quotaExpr, err := exprs.NewExprCtMark(test.setMark, test.TestsT.Parms, &cmp)
			if err != nil && !test.ExpectedFail {
				t.Errorf("Error creating expr Ct: %s", quotaExpr)
				return
			} else if err != nil && test.ExpectedFail {
				return
			}

			r, _ := nftest.AddTestRule(t, conn, quotaExpr)
			if r == nil && !test.ExpectedFail {
				t.Error("Error adding rule with Ct expression")
			}

			if !nftest.AreExprsValid(t, &test.TestsT, r) {
				return
			}

			if test.ExpectedFail {
				t.Errorf("test should have failed")
			}
		})
	}

}

func TestExprCtState(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	type ctTestsT struct {
		nftest.TestsT
		setMark bool
	}

	tests := []nftest.TestsT{
		{
			Name:  "test-ct-single-state",
			Parms: "",
			Values: []*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_CT_STATE,
					Value: exprs.CT_STATE_NEW,
				},
			},
			ExpectedExprsNum: 2,
			ExpectedExprs: []interface{}{
				&expr.Ct{
					Register: 1, SourceRegister: false, Key: expr.CtKeySTATE,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
					Xor:            binaryutil.NativeEndian.PutUint32(0),
				},
			},
			ExpectedFail: false,
		},
		{
			Name:  "test-ct-multiple-states",
			Parms: "",
			Values: []*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_CT_STATE,
					Value: fmt.Sprint(exprs.CT_STATE_NEW, ",", exprs.CT_STATE_ESTABLISHED),
				},
			},
			ExpectedExprsNum: 2,
			ExpectedExprs: []interface{}{
				&expr.Ct{
					Register: 1, SourceRegister: false, Key: expr.CtKeySTATE,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW | expr.CtStateBitESTABLISHED),
					Xor:            binaryutil.NativeEndian.PutUint32(0),
				},
			},
			ExpectedFail: false,
		},
		{
			Name:  "test-invalid-ct-state",
			Parms: "",
			Values: []*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_CT_STATE,
					Value: "xxx",
				},
			},
			ExpectedExprsNum: 2,
			ExpectedExprs:    []interface{}{},
			ExpectedFail:     true,
		},
		{
			Name:  "test-invalid-ct-states",
			Parms: "",
			Values: []*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_CT_STATE,
					Value: "new,xxx",
				},
			},
			ExpectedExprsNum: 2,
			ExpectedExprs:    []interface{}{},
			ExpectedFail:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			quotaExpr, err := exprs.NewExprCtState(test.Values)
			if err != nil && !test.ExpectedFail {
				t.Errorf("Error creating expr Ct: %s", quotaExpr)
				return
			} else if err != nil && test.ExpectedFail {
				return
			}

			r, _ := nftest.AddTestRule(t, conn, quotaExpr)
			if r == nil && !test.ExpectedFail {
				t.Error("Error adding rule with Quota expression")
			}

			if !nftest.AreExprsValid(t, &test, r) {
				return
			}

			if test.ExpectedFail {
				t.Errorf("test should have failed")
			}
		})
	}

}
