package exprs_test

import (
	"fmt"
	"reflect"
	"testing"

	exprs "github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestExprProtocol(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	testProtos := []string{
		exprs.NFT_PROTO_TCP,
		exprs.NFT_PROTO_UDP,
		exprs.NFT_PROTO_UDPLITE,
		exprs.NFT_PROTO_SCTP,
		exprs.NFT_PROTO_DCCP,
		exprs.NFT_PROTO_ICMP,
		exprs.NFT_PROTO_ICMPv6,
	}
	protoValues := []byte{
		unix.IPPROTO_TCP,
		unix.IPPROTO_UDP,
		unix.IPPROTO_UDPLITE,
		unix.IPPROTO_SCTP,
		unix.IPPROTO_DCCP,
		unix.IPPROTO_ICMP,
		unix.IPPROTO_ICMPV6,
	}

	for idx, proto := range testProtos {
		t.Run(fmt.Sprint("test-protoExpr-", proto), func(t *testing.T) {
			protoExpr, err := exprs.NewExprProtocol(proto)
			if err != nil {
				t.Errorf("%s - Error creating expr Log: %s", proto, protoExpr)
				return
			}
			r, _ := nftest.AddTestRule(t, conn, protoExpr)
			if r == nil {
				t.Errorf("Error adding rule with proto %s expression", proto)
			}
			if len(r.Exprs) != 2 {
				t.Errorf("%s - expected 2 Expressions, found %d", proto, len(r.Exprs))
			}
			e := r.Exprs[0]
			meta, ok := e.(*expr.Meta)
			if !ok {
				t.Errorf("%s - invalid proto expr: %T", proto, e)
			}
			//fmt.Printf("%s, %+v\n", reflect.TypeOf(e).String(), e)
			if reflect.TypeOf(e).String() != "*expr.Meta" {
				t.Errorf("%s - first expression should be *expr.Meta, instead of: %s", proto, reflect.TypeOf(e))
			}
			if meta.Key != expr.MetaKeyL4PROTO {
				t.Errorf("%s - invalid proto expr.Meta.Key: %d", proto, expr.MetaKeyL4PROTO)
			}

			e = r.Exprs[1]
			cmp, ok := e.(*expr.Cmp)
			if !ok {
				t.Errorf("%s - invalid proto cmp expr: %T", proto, e)
			}
			//fmt.Printf("%s, %+v\n", reflect.TypeOf(e).String(), e)
			if reflect.TypeOf(e).String() != "*expr.Cmp" {
				t.Errorf("%s - second expression should be *expr.Cmp, instead of: %s", proto, reflect.TypeOf(e))
			}
			if cmp.Op != expr.CmpOpEq {
				t.Errorf("%s - expr.Cmp should be CmpOpEq, instead of: %d", proto, cmp.Op)
			}
			if cmp.Data[0] != protoValues[idx] {
				t.Errorf("%s - expr.Data differs: %d<->%d", proto, cmp.Data, protoValues[idx])
			}
		})
	}
}
