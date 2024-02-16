package exprs_test

import (
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables/expr"
)

func TestExprQuota(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	tests := []nftest.TestsT{
		{
			"test-quota-over-bytes-12345",
			"", // family
			"", // parms
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_OVER,
					Value: "",
				},
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_UNIT_BYTES,
					Value: "12345",
				},
			},
			1,
			[]interface{}{
				&expr.Quota{
					Bytes:    uint64(12345),
					Consumed: 0,
					Over:     true,
				},
			},
			false,
		},
		{
			"test-quota-over-kbytes-1",
			"", // family
			"", // parms
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_OVER,
					Value: "",
				},
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_UNIT_KB,
					Value: "1",
				},
			},
			1,
			[]interface{}{
				&expr.Quota{
					Bytes:    uint64(1024),
					Consumed: 0,
					Over:     true,
				},
			},
			false,
		},
		{
			"test-quota-over-mbytes-1",
			"", // family
			"", // parms
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_OVER,
					Value: "",
				},
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_UNIT_MB,
					Value: "1",
				},
			},
			1,
			[]interface{}{
				&expr.Quota{
					Bytes:    uint64(1024 * 1024),
					Consumed: 0,
					Over:     true,
				},
			},
			false,
		},
		{
			"test-quota-over-gbytes-1",
			"", // family
			"", // parms
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_OVER,
					Value: "",
				},
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_UNIT_GB,
					Value: "1",
				},
			},
			1,
			[]interface{}{
				&expr.Quota{
					Bytes:    uint64(1024 * 1024 * 1024),
					Consumed: 0,
					Over:     true,
				},
			},
			false,
		},
		{
			"test-quota-until-gbytes-1",
			"", // family
			"", // parms
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_UNIT_GB,
					Value: "1",
				},
			},
			1,
			[]interface{}{
				&expr.Quota{
					Bytes:    uint64(1024 * 1024 * 1024),
					Consumed: 0,
					Over:     false,
				},
			},
			false,
		},
		{
			"test-quota-consumed-bytes-1024",
			"", // family
			"", // parms
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_UNIT_GB,
					Value: "1",
				},
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_USED,
					Value: "1024",
				},
			},
			1,
			[]interface{}{
				&expr.Quota{
					Bytes:    uint64(1024 * 1024 * 1024),
					Consumed: 1024,
					Over:     false,
				},
			},
			false,
		},
		{
			"test-invalid-quota-key",
			"", // family
			"", // parms
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   "gbyte",
					Value: "1",
				},
			},
			1,
			[]interface{}{},
			true,
		},
		{
			"test-invalid-quota-value",
			"", // family
			"", // parms
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_UNIT_GB,
					Value: "1a",
				},
			},
			1,
			[]interface{}{},
			true,
		},
		{
			"test-invalid-quota-value",
			"", // family
			"", // parms
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_UNIT_GB,
					Value: "",
				},
			},
			1,
			[]interface{}{},
			true,
		},
		{
			"test-invalid-quota-bytes-0",
			"", // family
			"", // parms
			[]*config.ExprValues{
				&config.ExprValues{
					Key:   exprs.NFT_QUOTA_UNIT_GB,
					Value: "0",
				},
			},
			1,
			[]interface{}{},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			quotaExpr, err := exprs.NewQuota(test.Values)
			if err != nil && !test.ExpectedFail {
				t.Errorf("Error creating expr Quota: %s", quotaExpr)
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
