package exprs_test

import (
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

	tests := []nftest.TestsT{
		{
			"test-meta-mark",
			exprs.NFT_FAMILY_IP,
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
		t.Run(test.Name, func(t *testing.T) {
			cmp := expr.CmpOpEq
			metaExpr, err := exprs.NewExprMeta(test.Values, &cmp)
			if err != nil && !test.ExpectedFail {
				t.Errorf("Error creating expr Meta: %s", metaExpr)
				return
			} else if err != nil && test.ExpectedFail {
				return
			}

			r, _ := nftest.AddTestRule(t, conn, metaExpr)
			if r == nil && !test.ExpectedFail {
				t.Error("Error adding rule with Meta expression")
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
