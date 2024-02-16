package exprs_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables/expr"
)

func TestExprEther(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	values := []*config.ExprValues{
		&config.ExprValues{
			Key:   "ether",
			Value: "de:ad:be:af:ca:fe",
		},
	}

	etherExpr, err := exprs.NewExprEther(values)
	if err != nil {
		t.Errorf("Error creating Ether expression: %s, %+v", err, values)
	}

	r, _ := nftest.AddTestRule(t, conn, etherExpr)
	if r == nil {
		t.Error("Error adding Ether rule")
		return
	}
	if len(r.Exprs) != 4 {
		t.Errorf("invalid rule created, we expected 4 expressions, got: %d", len(r.Exprs))
	}

	/*
		expr Meta
		expr Cmp
		expr Payload
		expr Cmp
	*/

	t.Run("test-ether-expr meta", func(t *testing.T) {
		e := r.Exprs[0] // meta
		if reflect.TypeOf(e).String() != "*expr.Meta" {
			t.Errorf("first expression should be *expr.Meta, instead of: %s", reflect.TypeOf(e))
		}
		lMeta, ok := e.(*expr.Meta)
		if !ok {
			t.Errorf("invalid meta expr: %T", e)
		}
		if lMeta.Key != expr.MetaKeyIIFTYPE {
			t.Errorf("invalid meta Key: %d, instead of %d", lMeta.Key, expr.MetaKeyIIFTYPE)
		}
	})

	t.Run("test-ether-expr cmp", func(t *testing.T) {
		e := r.Exprs[1] // cmp
		if reflect.TypeOf(e).String() != "*expr.Cmp" {
			t.Errorf("second expression should be *expr.Cmp, instead of: %s", reflect.TypeOf(e))
		}
		lCmp, ok := e.(*expr.Cmp)
		if !ok {
			t.Errorf("invalid cmp expr: %T", e)
		}
		if !bytes.Equal(lCmp.Data, []byte{0x01, 0x00}) {
			t.Errorf("invalid cmp data: %v", lCmp.Data)
		}
	})

	t.Run("test-ether-expr payload", func(t *testing.T) {
		e := r.Exprs[2] // payload
		if reflect.TypeOf(e).String() != "*expr.Payload" {
			t.Errorf("third expression should be *expr.Payload, instead of: %s", reflect.TypeOf(e))
		}
		lPayload, ok := e.(*expr.Payload)
		if !ok {
			t.Errorf("invalid payload expr: %T", e)
		}
		if lPayload.Base != expr.PayloadBaseLLHeader || lPayload.Offset != 6 || lPayload.Len != 6 {
			t.Errorf("invalid payload data: %v", lPayload)
		}
	})

	t.Run("test-ether-expr cmp", func(t *testing.T) {
		e := r.Exprs[3] // cmp
		if reflect.TypeOf(e).String() != "*expr.Cmp" {
			t.Errorf("fourth expression should be *expr.Cmp, instead of: %s", reflect.TypeOf(e))
		}
		lCmp, ok := e.(*expr.Cmp)
		if !ok {
			t.Errorf("invalid cmp expr: %T", e)
		}
		if !bytes.Equal(lCmp.Data, []byte{222, 173, 190, 175, 202, 254}) {
			t.Errorf("invalid cmp data: %q", lCmp.Data)
		}
	})

}
