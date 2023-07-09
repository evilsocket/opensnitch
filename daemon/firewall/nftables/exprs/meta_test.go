package exprs_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func TestExprMeta(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	type metaTestsT struct {
		name             string
		family           string
		values           []*config.ExprValues
		expectedExprsNum int
		expectedExprs    []interface{}
		expectedFail     bool
	}

	tests := []metaTestsT{
		{
			"test-meta-mark",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_META_MARK,
					Value: "666",
				},
			},
			2,
			[]interface{}{
				&expr.Meta{
					Key:            expr.MetaKeyMARK,
					Register:       1,
					SourceRegister: false,
				},
				&expr.Cmp{
					Data: binaryutil.NativeEndian.PutUint32(uint32(666)),
				},
			},
			false,
		},
		{
			"test-meta-set-mark",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_META_SET_MARK,
					Value: "",
				},
				&config.ExprValues{
					Key:   exprs.NFT_META_MARK,
					Value: "666",
				},
			},
			2,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(666),
				},
				&expr.Meta{
					Key:            expr.MetaKeyMARK,
					Register:       1,
					SourceRegister: true,
				},
			},
			false,
		},
		{
			"test-meta-priority",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_META_PRIORITY,
					Value: "1",
				},
			},
			2,
			[]interface{}{
				&expr.Meta{
					Key:            expr.MetaKeyPRIORITY,
					Register:       1,
					SourceRegister: false,
				},
				&expr.Cmp{
					Data: binaryutil.NativeEndian.PutUint32(uint32(1)),
				},
			},
			false,
		},
		{
			"test-meta-skuid",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_META_SKUID,
					Value: "1",
				},
			},
			2,
			[]interface{}{
				&expr.Meta{
					Key:            expr.MetaKeySKUID,
					Register:       1,
					SourceRegister: false,
				},
				&expr.Cmp{
					Data: binaryutil.NativeEndian.PutUint32(uint32(1)),
				},
			},
			false,
		},
		{
			"test-meta-skgid",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_META_SKGID,
					Value: "1",
				},
			},
			2,
			[]interface{}{
				&expr.Meta{
					Key:            expr.MetaKeySKGID,
					Register:       1,
					SourceRegister: false,
				},
				&expr.Cmp{
					Data: binaryutil.NativeEndian.PutUint32(uint32(1)),
				},
			},
			false,
		},
		{
			"test-meta-protocol",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_META_PROTOCOL,
					Value: "15",
				},
			},
			2,
			[]interface{}{
				&expr.Meta{
					Key:            expr.MetaKeyPROTOCOL,
					Register:       1,
					SourceRegister: false,
				},
				&expr.Cmp{
					Data: binaryutil.NativeEndian.PutUint32(uint32(15)),
				},
			},
			false,
		},
		// tested more in depth in protocol_test.go
		{
			"test-meta-l4proto",
			exprs.NFT_FAMILY_IP,
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_META_L4PROTO,
					Value: "15",
				},
			},
			1,
			[]interface{}{
				&expr.Meta{
					Key:            expr.MetaKeyL4PROTO,
					Register:       1,
					SourceRegister: false,
				},
			},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmp := expr.CmpOpEq
			metaExpr, err := exprs.NewExprMeta(test.values, &cmp)
			if err != nil && !test.expectedFail {
				t.Errorf("Error creating expr Meta: %s", metaExpr)
				return
			} else if err != nil && test.expectedFail {
				return
			}

			r, _ := nftest.AddTestRule(t, conn, metaExpr)
			if r == nil && !test.expectedFail {
				t.Error("Error adding rule with Meta expression")
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
						t.Errorf("invalid Meta expr: %+v, %+v", lExpr, lExpect)
						return
					}
					if lExpr.Key != lExpect.Key || lExpr.Register != lExpect.Register {
						t.Errorf("invalid Meta.Key,\nreturned: %+v\nexpected: %+v\n", lExpr.Key, lExpect.Key)
					}
					if lExpr.SourceRegister != lExpect.SourceRegister {
						t.Errorf("invalid Meta.SourceRegister,\nreturned: %+v\nexpected: %+v\n", lExpr.SourceRegister, lExpect.SourceRegister)
					}
					if lExpr.Register != lExpect.Register {
						t.Errorf("invalid Meta.Register,\nreturned: %+v\nexpected: %+v\n", lExpr.SourceRegister, lExpect.SourceRegister)
					}

				case *expr.Immediate:
					lExpr, ok := e.(*expr.Immediate)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Immediate)
					if !ok || !okExpected {
						t.Errorf("invalid Immediate expr, got: %+v, expected: %+v", lExpr, lExpect)
						return
					}
					if !bytes.Equal(lExpr.Data, lExpect.Data) && !test.expectedFail {
						t.Errorf("invalid Immediate.Data, got: %+v, expected: %+v", lExpr.Data, lExpect.Data)
						return
					}

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
