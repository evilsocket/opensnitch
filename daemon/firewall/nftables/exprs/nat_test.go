package exprs_test

import (
	"bytes"
	"net"
	"reflect"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type natTestsT struct {
	name             string
	family           string
	parms            string
	values           []*config.ExprValues
	expectedExprsNum int
	expectedExprs    []interface{}
	expectedFail     bool
}

func TestExprVerdictSNAT(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	// TODO: test random, permanent, persistent flags.
	tests := []natTestsT{
		{
			"test-nat-snat-to-127001",
			exprs.NFT_FAMILY_IP,
			"to 127.0.0.1",
			nil,
			2,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.NAT{
					Type:        expr.NATTypeSourceNAT,
					Family:      unix.NFPROTO_IPV4,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					RegAddrMin:  1,
				},
			},
			false,
		},
		{
			"test-nat-snat-127001",
			exprs.NFT_FAMILY_IP,
			"127.0.0.1",
			nil,
			2,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.NAT{
					Type:        expr.NATTypeSourceNAT,
					Family:      unix.NFPROTO_IPV4,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					RegAddrMin:  1,
				},
			},
			false,
		},
		{
			"test-nat-snat-to-127001:12345",
			exprs.NFT_FAMILY_IP,
			"to 127.0.0.1:12345",
			nil,
			3,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.Immediate{
					Register: uint32(2),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.NAT{
					Type:        expr.NATTypeSourceNAT,
					Family:      unix.NFPROTO_IPV4,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					RegAddrMin:  1,
					RegProtoMin: 2,
				},
			},
			false,
		},
		{
			"test-nat-snat-to-:12345",
			exprs.NFT_FAMILY_IP,
			"to :12345",
			nil,
			2,
			[]interface{}{
				&expr.Immediate{
					Register: uint32(2),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.NAT{
					Type:        expr.NATTypeSourceNAT,
					Family:      unix.NFPROTO_IPV4,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					RegAddrMin:  0,
					RegProtoMin: 2,
				},
			},
			false,
		},
		{
			"test-nat-snat-127001:12345",
			exprs.NFT_FAMILY_IP,
			"127.0.0.1:12345",
			nil,
			3,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.Immediate{
					Register: uint32(2),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.NAT{
					Type:        expr.NATTypeSourceNAT,
					Family:      unix.NFPROTO_IPV4,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					RegAddrMin:  1,
					RegProtoMin: 2,
				},
			},
			false,
		},
		{
			"test-invalid-nat-snat-to-",
			exprs.NFT_FAMILY_IP,
			"to",
			nil,
			3,
			[]interface{}{},
			true,
		},
		{
			"test-invalid-nat-snat-to-invalid-ip",
			exprs.NFT_FAMILY_IP,
			"to 127..0.0.1",
			nil,
			3,
			[]interface{}{},
			true,
		},
		{
			"test-invalid-nat-snat-to-invalid-port",
			exprs.NFT_FAMILY_IP,
			"to 127.0.0.1:aaa",
			nil,
			3,
			[]interface{}{},
			true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_SNAT, test.parms)
			if !test.expectedFail && verdExpr == nil {
				t.Errorf("error creating snat verdict")
			} else if test.expectedFail && verdExpr == nil {
				return
			}
			r, _ := nftest.AddTestSNATRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule")
				return
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
						t.Errorf("invalid Immediate expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if !bytes.Equal(lExpr.Data, lExpect.Data) && !test.expectedFail {
						t.Errorf("invalid Immediate.Data,\ngot: %+v,\nexpected: %+v", lExpr.Data, lExpect.Data)
						return
					}

				case *expr.TProxy:
					lExpr, ok := e.(*expr.TProxy)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.TProxy)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.Family != lExpect.Family || lExpr.TableFamily != lExpect.TableFamily || lExpr.RegPort != lExpect.RegPort {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Redir:
					lExpr, ok := e.(*expr.Redir)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Redir)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.RegisterProtoMin != lExpect.RegisterProtoMin {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Masq:
					lExpr, ok := e.(*expr.Masq)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Masq)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.ToPorts != lExpect.ToPorts ||
						lExpr.Random != lExpect.Random ||
						lExpr.FullyRandom != lExpect.FullyRandom ||
						lExpr.Persistent != lExpect.Persistent {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.NAT:
					lExpr, ok := e.(*expr.NAT)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.NAT)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.RegProtoMin != lExpect.RegProtoMin ||
						lExpr.RegAddrMin != lExpect.RegAddrMin ||
						lExpr.Random != lExpect.Random ||
						lExpr.FullyRandom != lExpect.FullyRandom ||
						lExpr.Persistent != lExpect.Persistent {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
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

func TestExprVerdictDNAT(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	tests := []natTestsT{
		{
			"test-nat-dnat-to-127001",
			exprs.NFT_FAMILY_IP,
			"to 127.0.0.1",
			nil,
			2,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.NAT{
					Type:        expr.NATTypeDestNAT,
					Family:      unix.NFPROTO_IPV4,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					RegAddrMin:  1,
				},
			},
			false,
		},
		{
			"test-nat-dnat-127001",
			exprs.NFT_FAMILY_IP,
			"127.0.0.1",
			nil,
			2,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.NAT{
					Type:        expr.NATTypeDestNAT,
					Family:      unix.NFPROTO_IPV4,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					RegAddrMin:  1,
				},
			},
			false,
		},
		{
			"test-nat-dnat-to-127001:12345",
			exprs.NFT_FAMILY_IP,
			"to 127.0.0.1:12345",
			nil,
			3,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.Immediate{
					Register: uint32(2),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.NAT{
					Type:        expr.NATTypeDestNAT,
					Family:      unix.NFPROTO_IPV4,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					RegAddrMin:  1,
					RegProtoMin: 2,
				},
			},
			false,
		},
		{
			"test-nat-dnat-to-:12345",
			exprs.NFT_FAMILY_IP,
			"to :12345",
			nil,
			2,
			[]interface{}{
				&expr.Immediate{
					Register: uint32(2),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.NAT{
					Type:        expr.NATTypeDestNAT,
					Family:      unix.NFPROTO_IPV4,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					RegAddrMin:  0,
					RegProtoMin: 2,
				},
			},
			false,
		},
		{
			"test-nat-dnat-127001:12345",
			exprs.NFT_FAMILY_IP,
			"127.0.0.1:12345",
			nil,
			3,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.Immediate{
					Register: uint32(2),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.NAT{
					Type:        expr.NATTypeDestNAT,
					Family:      unix.NFPROTO_IPV4,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					RegAddrMin:  1,
					RegProtoMin: 2,
				},
			},
			false,
		},
		{
			"test-invalid-nat-dnat-to-",
			exprs.NFT_FAMILY_IP,
			"to",
			nil,
			3,
			[]interface{}{},
			true,
		},
		{
			"test-invalid-nat-dnat-to-invalid-ip",
			exprs.NFT_FAMILY_IP,
			"to 127..0.0.1",
			nil,
			3,
			[]interface{}{},
			true,
		},
		{
			"test-invalid-nat-dnat-to-invalid-port",
			exprs.NFT_FAMILY_IP,
			"to 127.0.0.1:aaa",
			nil,
			3,
			[]interface{}{},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_DNAT, test.parms)
			if !test.expectedFail && verdExpr == nil {
				t.Errorf("error creating verdict")
			} else if test.expectedFail && verdExpr == nil {
				return
			}
			r, _ := nftest.AddTestDNATRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule")
				return
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
						t.Errorf("invalid Immediate expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if !bytes.Equal(lExpr.Data, lExpect.Data) && !test.expectedFail {
						t.Errorf("invalid Immediate.Data,\ngot: %+v,\nexpected: %+v", lExpr.Data, lExpect.Data)
						return
					}

				case *expr.TProxy:
					lExpr, ok := e.(*expr.TProxy)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.TProxy)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.Family != lExpect.Family || lExpr.TableFamily != lExpect.TableFamily || lExpr.RegPort != lExpect.RegPort {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Redir:
					lExpr, ok := e.(*expr.Redir)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Redir)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.RegisterProtoMin != lExpect.RegisterProtoMin {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Masq:
					lExpr, ok := e.(*expr.Masq)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Masq)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.ToPorts != lExpect.ToPorts ||
						lExpr.Random != lExpect.Random ||
						lExpr.FullyRandom != lExpect.FullyRandom ||
						lExpr.Persistent != lExpect.Persistent {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.NAT:
					lExpr, ok := e.(*expr.NAT)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.NAT)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.RegProtoMin != lExpect.RegProtoMin ||
						lExpr.RegAddrMin != lExpect.RegAddrMin ||
						lExpr.Random != lExpect.Random ||
						lExpr.FullyRandom != lExpect.FullyRandom ||
						lExpr.Persistent != lExpect.Persistent {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
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

func TestExprVerdictMasquerade(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	tests := []natTestsT{
		{
			"test-nat-masq-to-:12345",
			exprs.NFT_FAMILY_IP,
			"to :12345",
			nil,
			2,
			[]interface{}{
				&expr.Immediate{
					Register: uint32(1),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.Masq{
					ToPorts:     true,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
				},
			},
			false,
		},
		{
			"test-nat-masq-flags",
			exprs.NFT_FAMILY_IP,
			"random,fully-random,persistent",
			nil,
			1,
			[]interface{}{
				&expr.Masq{
					ToPorts:     false,
					Random:      true,
					FullyRandom: true,
					Persistent:  true,
				},
			},
			false,
		},
		{
			"test-nat-masq-empty",
			exprs.NFT_FAMILY_IP,
			"",
			nil,
			1,
			[]interface{}{
				&expr.Masq{},
			},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_MASQUERADE, test.parms)
			if !test.expectedFail && verdExpr == nil {
				t.Errorf("error creating verdict")
			} else if test.expectedFail && verdExpr == nil {
				return
			}
			r, _ := nftest.AddTestSNATRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule")
				return
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
						t.Errorf("invalid Immediate expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if !bytes.Equal(lExpr.Data, lExpect.Data) && !test.expectedFail {
						t.Errorf("invalid Immediate.Data,\ngot: %+v,\nexpected: %+v", lExpr.Data, lExpect.Data)
						return
					}

				case *expr.TProxy:
					lExpr, ok := e.(*expr.TProxy)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.TProxy)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.Family != lExpect.Family || lExpr.TableFamily != lExpect.TableFamily || lExpr.RegPort != lExpect.RegPort {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Redir:
					lExpr, ok := e.(*expr.Redir)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Redir)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.RegisterProtoMin != lExpect.RegisterProtoMin {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Masq:
					lExpr, ok := e.(*expr.Masq)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Masq)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.ToPorts != lExpect.ToPorts ||
						lExpr.Random != lExpect.Random ||
						lExpr.FullyRandom != lExpect.FullyRandom ||
						lExpr.Persistent != lExpect.Persistent {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.NAT:
					lExpr, ok := e.(*expr.NAT)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.NAT)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.RegProtoMin != lExpect.RegProtoMin ||
						lExpr.RegAddrMin != lExpect.RegAddrMin ||
						lExpr.Random != lExpect.Random ||
						lExpr.FullyRandom != lExpect.FullyRandom ||
						lExpr.Persistent != lExpect.Persistent {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
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

func TestExprVerdictRedirect(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	tests := []natTestsT{
		{
			"test-nat-redir-to-127001:12345",
			exprs.NFT_FAMILY_IP,
			"to 127.0.0.1:12345",
			nil,
			3,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.Immediate{
					Register: uint32(1),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.Redir{
					RegisterProtoMin: 1,
				},
			},
			false,
		},
		{
			"test-nat-redir-to-:12345",
			exprs.NFT_FAMILY_IP,
			"to :12345",
			nil,
			2,
			[]interface{}{
				&expr.Immediate{
					Register: uint32(1),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.Redir{
					RegisterProtoMin: 1,
				},
			},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_REDIRECT, test.parms)
			if !test.expectedFail && verdExpr == nil {
				t.Errorf("error creating verdict")
			} else if test.expectedFail && verdExpr == nil {
				return
			}
			r, _ := nftest.AddTestDNATRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule")
				return
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
						t.Errorf("invalid Immediate expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if !bytes.Equal(lExpr.Data, lExpect.Data) && !test.expectedFail {
						t.Errorf("invalid Immediate.Data,\ngot: %+v,\nexpected: %+v", lExpr.Data, lExpect.Data)
						return
					}

				case *expr.TProxy:
					lExpr, ok := e.(*expr.TProxy)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.TProxy)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.Family != lExpect.Family || lExpr.TableFamily != lExpect.TableFamily || lExpr.RegPort != lExpect.RegPort {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Redir:
					lExpr, ok := e.(*expr.Redir)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Redir)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.RegisterProtoMin != lExpect.RegisterProtoMin {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Masq:
					lExpr, ok := e.(*expr.Masq)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Masq)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.ToPorts != lExpect.ToPorts ||
						lExpr.Random != lExpect.Random ||
						lExpr.FullyRandom != lExpect.FullyRandom ||
						lExpr.Persistent != lExpect.Persistent {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.NAT:
					lExpr, ok := e.(*expr.NAT)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.NAT)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.RegProtoMin != lExpect.RegProtoMin ||
						lExpr.RegAddrMin != lExpect.RegAddrMin ||
						lExpr.Random != lExpect.Random ||
						lExpr.FullyRandom != lExpect.FullyRandom ||
						lExpr.Persistent != lExpect.Persistent {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
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

func TestExprVerdictTProxy(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	tests := []natTestsT{
		{
			"test-nat-tproxy-to-127001:12345",
			exprs.NFT_FAMILY_IP,
			"to 127.0.0.1:12345",
			nil,
			4,
			[]interface{}{
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP("127.0.0.1").To4(),
				},
				&expr.Immediate{
					Register: uint32(1),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.TProxy{
					Family:      byte(nftables.TableFamilyIPv4),
					TableFamily: byte(nftables.TableFamilyIPv4),
					RegPort:     1,
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
			false,
		},
		{
			"test-nat-tproxy-to-:12345",
			exprs.NFT_FAMILY_IP,
			"to :12345",
			nil,
			3,
			[]interface{}{
				&expr.Immediate{
					Register: uint32(1),
					Data:     binaryutil.BigEndian.PutUint16(uint16(12345)),
				},
				&expr.TProxy{
					Family:      byte(nftables.TableFamilyIPv4),
					TableFamily: byte(nftables.TableFamilyIPv4),
					RegPort:     1,
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_TPROXY, test.parms)
			if !test.expectedFail && verdExpr == nil {
				t.Errorf("error creating verdict")
			} else if test.expectedFail && verdExpr == nil {
				return
			}
			r, _ := nftest.AddTestDNATRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule")
				return
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
						t.Errorf("invalid Immediate expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if !bytes.Equal(lExpr.Data, lExpect.Data) && !test.expectedFail {
						t.Errorf("invalid Immediate.Data,\ngot: %+v,\nexpected: %+v", lExpr.Data, lExpect.Data)
						return
					}

				case *expr.TProxy:
					lExpr, ok := e.(*expr.TProxy)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.TProxy)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.Family != lExpect.Family || lExpr.TableFamily != lExpect.TableFamily || lExpr.RegPort != lExpect.RegPort {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Redir:
					lExpr, ok := e.(*expr.Redir)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Redir)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.RegisterProtoMin != lExpect.RegisterProtoMin {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.Masq:
					lExpr, ok := e.(*expr.Masq)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.Masq)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.ToPorts != lExpect.ToPorts ||
						lExpr.Random != lExpect.Random ||
						lExpr.FullyRandom != lExpect.FullyRandom ||
						lExpr.Persistent != lExpect.Persistent {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}

				case *expr.NAT:
					lExpr, ok := e.(*expr.NAT)
					lExpect, okExpected := test.expectedExprs[idx].(*expr.NAT)
					if !ok || !okExpected {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
						return
					}
					if lExpr.RegProtoMin != lExpect.RegProtoMin ||
						lExpr.RegAddrMin != lExpect.RegAddrMin ||
						lExpr.Random != lExpect.Random ||
						lExpr.FullyRandom != lExpect.FullyRandom ||
						lExpr.Persistent != lExpect.Persistent {
						t.Errorf("invalid TProxy expr,\ngot: %+v,\nexpected: %+v", lExpr, lExpect)
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
