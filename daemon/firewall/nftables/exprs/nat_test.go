package exprs_test

import (
	"net"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestExprVerdictSNAT(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	// TODO: test random, permanent, persistent flags.
	tests := []nftest.TestsT{
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
		t.Run(test.Name, func(t *testing.T) {

			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_SNAT, test.Parms)
			if !test.ExpectedFail && verdExpr == nil {
				t.Errorf("error creating snat verdict")
			} else if test.ExpectedFail && verdExpr == nil {
				return
			}
			r, _ := nftest.AddTestSNATRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule")
				return
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

func TestExprVerdictDNAT(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	tests := []nftest.TestsT{
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
		t.Run(test.Name, func(t *testing.T) {

			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_DNAT, test.Parms)
			if !test.ExpectedFail && verdExpr == nil {
				t.Errorf("error creating verdict")
			} else if test.ExpectedFail && verdExpr == nil {
				return
			}
			r, _ := nftest.AddTestDNATRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule")
				return
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

func TestExprVerdictMasquerade(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	tests := []nftest.TestsT{
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
		t.Run(test.Name, func(t *testing.T) {

			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_MASQUERADE, test.Parms)
			if !test.ExpectedFail && verdExpr == nil {
				t.Errorf("error creating verdict")
			} else if test.ExpectedFail && verdExpr == nil {
				return
			}
			r, _ := nftest.AddTestSNATRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule")
				return
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

func TestExprVerdictRedirect(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	tests := []nftest.TestsT{
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
		t.Run(test.Name, func(t *testing.T) {

			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_REDIRECT, test.Parms)
			if !test.ExpectedFail && verdExpr == nil {
				t.Errorf("error creating verdict")
			} else if test.ExpectedFail && verdExpr == nil {
				return
			}
			r, _ := nftest.AddTestDNATRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule")
				return
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

func TestExprVerdictTProxy(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	tests := []nftest.TestsT{
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
		t.Run(test.Name, func(t *testing.T) {

			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_TPROXY, test.Parms)
			if !test.ExpectedFail && verdExpr == nil {
				t.Errorf("error creating verdict")
			} else if test.ExpectedFail && verdExpr == nil {
				return
			}
			r, _ := nftest.AddTestDNATRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule")
				return
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
