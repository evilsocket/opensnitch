package exprs_test

import (
	"reflect"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	exprs "github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables/expr"
)

func TestExprLog(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	statem := config.ExprStatement{
		Op:   "==",
		Name: "log",
		Values: []*config.ExprValues{
			&config.ExprValues{
				Key:   "prefix",
				Value: "counter-test",
			},
			&config.ExprValues{
				Key:   "level",
				Value: exprs.NFT_LOG_LEVEL_AUDIT,
			},
		},
	}

	logExpr, err := exprs.NewExprLog(&statem)
	if err != nil {
		t.Errorf("Error creating expr Log: %s", logExpr)
		return
	}
	r, _ := nftest.AddTestRule(t, conn, logExpr)
	if r == nil {
		t.Error("Error adding rule with log expression")
	}
	e := r.Exprs[0]
	if reflect.TypeOf(e).String() != "*expr.Log" {
		t.Errorf("first expression should be *expr.Log, instead of: %s", reflect.TypeOf(e))
	}
	lExpr, ok := e.(*expr.Log)
	if !ok {
		t.Errorf("invalid log prefix: %T", e)
	}
	if lExpr.Key != 36 {
		t.Errorf("invalid log prefix Key: %d, instead of 4", lExpr.Key)
	}
	if lExpr.Level != expr.LogLevelAudit {
		t.Errorf("invalid log level: %d, instead of %s", lExpr.Level, statem.Values[1].Value)
	}
	if string(lExpr.Data) != "counter-test" {
		t.Errorf("log prefix not set: %s", lExpr.Data)
	}
	//fmt.Printf("%+v\n", lExpr)
}
