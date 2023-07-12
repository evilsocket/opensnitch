package exprs_test

import (
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	exprs "github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestExprLog(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	type logTestsT struct {
		nftest.TestsT
		statem *config.ExprStatement
	}
	tests := []logTestsT{
		{
			TestsT: nftest.TestsT{
				Name: "test-log-prefix-simple",
				Values: []*config.ExprValues{
					&config.ExprValues{
						Key:   "prefix",
						Value: "counter-test",
					},
				},
				ExpectedExprs: []interface{}{
					&expr.Log{
						Key:  1 << unix.NFTA_LOG_PREFIX,
						Data: []byte("counter-test"),
					},
				},
				ExpectedExprsNum: 1,
				ExpectedFail:     false,
			},
			statem: &config.ExprStatement{
				Op:   "==",
				Name: "log",
			},
		},
		{
			TestsT: nftest.TestsT{
				Name: "test-log-prefix-emerg",
				Values: []*config.ExprValues{
					&config.ExprValues{
						Key:   exprs.NFT_LOG_PREFIX,
						Value: "counter-test-emerg",
					},
					&config.ExprValues{
						Key:   exprs.NFT_LOG_LEVEL,
						Value: exprs.NFT_LOG_LEVEL_EMERG,
					},
				},
				ExpectedExprs: []interface{}{
					&expr.Log{
						Key:   (1 << unix.NFTA_LOG_PREFIX) | (1 << unix.NFTA_LOG_LEVEL),
						Level: expr.LogLevelEmerg,
						Data:  []byte("counter-test-emerg"),
					},
				},
				ExpectedExprsNum: 1,
				ExpectedFail:     false,
			},
			statem: &config.ExprStatement{
				Op:   "==",
				Name: "log",
			},
		},
		{
			TestsT: nftest.TestsT{
				Name: "test-invalid-log-prefix",
				Values: []*config.ExprValues{
					&config.ExprValues{
						Key:   exprs.NFT_LOG_PREFIX,
						Value: "",
					},
					&config.ExprValues{
						Key:   exprs.NFT_LOG_LEVEL,
						Value: exprs.NFT_LOG_LEVEL_EMERG,
					},
				},
				ExpectedExprs:    []interface{}{},
				ExpectedExprsNum: 0,
				ExpectedFail:     true,
			},
			statem: &config.ExprStatement{
				Op:   "==",
				Name: "log",
			},
		},
		{
			TestsT: nftest.TestsT{
				Name: "test-invalid-log-level",
				Values: []*config.ExprValues{
					&config.ExprValues{
						Key:   exprs.NFT_LOG_PREFIX,
						Value: "counter-invalid-level",
					},
					&config.ExprValues{
						Key:   exprs.NFT_LOG_LEVEL,
						Value: "",
					},
				},
				ExpectedExprs:    []interface{}{},
				ExpectedExprsNum: 0,
				ExpectedFail:     true,
			},
			statem: &config.ExprStatement{
				Op:   "==",
				Name: "log",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {

			test.statem.Values = test.TestsT.Values
			logExpr, err := exprs.NewExprLog(test.statem)
			if err != nil && !test.ExpectedFail {
				t.Errorf("Error creating expr Log: %s", logExpr)
				return
			} else if err != nil && test.ExpectedFail {
				return
			}
			r, _ := nftest.AddTestRule(t, conn, logExpr)
			if r == nil {
				t.Error("Error adding rule with log expression")
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
