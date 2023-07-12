package exprs_test

import (
	"net"
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

	tests := []nftest.TestsT{
		{
			"test-ip-daddr",
			exprs.NFT_FAMILY_IP,
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
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
		t.Run(test.Name, func(t *testing.T) {
			ipExpr, err := exprs.NewExprIP(test.Family, test.Values, expr.CmpOpEq)
			if err != nil && !test.ExpectedFail {
				t.Errorf("Error creating expr IP: %s", ipExpr)
				return
			} else if err != nil && test.ExpectedFail {
				return
			}

			r, _ := nftest.AddTestRule(t, conn, ipExpr)
			if r == nil && !test.ExpectedFail {
				t.Error("Error adding rule with IP expression")
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
