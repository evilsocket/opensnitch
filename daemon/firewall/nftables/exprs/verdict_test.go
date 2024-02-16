package exprs_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type verdictTestsT struct {
	name         string
	verdict      string
	parms        string
	expectedExpr string
	expectedKind expr.VerdictKind
}

func TestExprVerdict(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	// we must create a custom chain before using JUMP verdict.
	tbl, _ := nftest.Fw.AddTable("yyy", exprs.NFT_FAMILY_INET)
	nftest.Fw.Conn.AddChain(&nftables.Chain{
		Name:  "custom-chain",
		Table: tbl,
	})
	nftest.Fw.Commit()

	verdictTests := []verdictTestsT{
		{"test-accept", exprs.VERDICT_ACCEPT, "", "*expr.Verdict", expr.VerdictAccept},
		{"test-AcCept", "AcCePt", "", "*expr.Verdict", expr.VerdictAccept},
		{"test-ACCEPT", "ACCEPT", "", "*expr.Verdict", expr.VerdictAccept},
		{"test-drop", exprs.VERDICT_DROP, "", "*expr.Verdict", expr.VerdictDrop},
		//{"test-stop", exprs.VERDICT_STOP, "", "*expr.Verdict", expr.VerdictStop},
		{"test-return", exprs.VERDICT_RETURN, "", "*expr.Verdict", expr.VerdictReturn},
		{"test-jump", exprs.VERDICT_JUMP, "custom-chain", "*expr.Verdict", expr.VerdictJump},
		// empty verdict must be valid at this level.
		// it can be used with "log" or "ct set mark"
		{"test-empty-verdict", "", "", "*expr.Verdict", expr.VerdictAccept},
	}

	for _, test := range verdictTests {
		t.Run(test.name, func(t *testing.T) {
			verdExpr := exprs.NewExprVerdict(test.verdict, test.parms)
			r, _ := nftest.AddTestRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule with verdict expression %s", test.verdict)
				return
			}
			if test.name == "test-empty-verdict" {
				return
			}
			e := r.Exprs[0]
			if reflect.TypeOf(e).String() != test.expectedExpr {
				t.Errorf("first expression should be *expr.Verdict, instead of: %s", reflect.TypeOf(e))
				return
			}
			verd, ok := e.(*expr.Verdict)
			if !ok {
				t.Errorf("invalid verdict: %T", e)
				return
			}
			if verd.Kind != test.expectedKind {
				t.Errorf("invalid verdict kind: %+v, expected: %+v", verd.Kind, test.expectedKind)
				return
			}
		})
	}
}

func TestExprVerdictReject(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	type rejectTests struct {
		name     string
		parms    string
		what     string
		family   string
		parmType byte
		parmCode byte
	}
	tests := []rejectTests{
		{
			"test-reject-tcp-RST",
			"with tcp reset",
			exprs.NFT_PROTO_TCP,
			exprs.NFT_FAMILY_INET,
			unix.NFT_REJECT_TCP_RST,
			unix.NFT_REJECT_TCP_RST,
		},

		{
			"test-reject-icmp-host-unreachable",
			fmt.Sprint("with icmp ", exprs.ICMP_HOST_UNREACHABLE),
			exprs.NFT_FAMILY_IP,
			exprs.NFT_PROTO_ICMP,
			unix.NFT_REJECT_ICMP_UNREACH,
			exprs.GetICMPRejectCode(exprs.ICMP_HOST_UNREACHABLE),
		},
		{
			"test-reject-icmp-addr-unreachable",
			fmt.Sprint("with icmp ", exprs.ICMP_ADDR_UNREACHABLE),
			exprs.NFT_FAMILY_IP,
			exprs.NFT_PROTO_ICMP,
			unix.NFT_REJECT_ICMP_UNREACH,
			exprs.GetICMPRejectCode(exprs.ICMP_ADDR_UNREACHABLE),
		},
		{
			"test-reject-icmp-prot-unreachable",
			fmt.Sprint("with icmp ", exprs.ICMP_PROT_UNREACHABLE),
			exprs.NFT_FAMILY_IP,
			exprs.NFT_PROTO_ICMP,
			unix.NFT_REJECT_ICMP_UNREACH,
			exprs.GetICMPRejectCode(exprs.ICMP_PROT_UNREACHABLE),
		},
		{
			"test-reject-icmp-port-unreachable",
			fmt.Sprint("with icmp ", exprs.ICMP_PORT_UNREACHABLE),
			exprs.NFT_FAMILY_IP,
			exprs.NFT_PROTO_ICMP,
			unix.NFT_REJECT_ICMP_UNREACH,
			exprs.GetICMPRejectCode(exprs.ICMP_PORT_UNREACHABLE),
		},
		{
			"test-reject-icmp-admin-prohibited",
			fmt.Sprint("with icmp ", exprs.ICMP_ADMIN_PROHIBITED),
			exprs.NFT_FAMILY_IP,
			exprs.NFT_PROTO_ICMP,
			unix.NFT_REJECT_ICMP_UNREACH,
			exprs.GetICMPRejectCode(exprs.ICMP_ADMIN_PROHIBITED),
		},
		{
			"test-reject-icmp-host-prohibited",
			fmt.Sprint("with icmp ", exprs.ICMP_HOST_PROHIBITED),
			exprs.NFT_FAMILY_IP,
			exprs.NFT_PROTO_ICMP,
			unix.NFT_REJECT_ICMP_UNREACH,
			exprs.GetICMPRejectCode(exprs.ICMP_HOST_PROHIBITED),
		},
		{
			"test-reject-icmp-net-prohibited",
			fmt.Sprint("with icmp ", exprs.ICMP_NET_PROHIBITED),
			exprs.NFT_FAMILY_IP,
			exprs.NFT_PROTO_ICMP,
			unix.NFT_REJECT_ICMP_UNREACH,
			exprs.GetICMPRejectCode(exprs.ICMP_NET_PROHIBITED),
		},

		// icmpx
		{
			"test-reject-icmpx-net-unreachable",
			fmt.Sprint("with icmpx ", exprs.ICMP_NET_UNREACHABLE),
			exprs.NFT_FAMILY_INET,
			exprs.NFT_PROTO_ICMPX,
			unix.NFT_REJECT_ICMPX_UNREACH,
			exprs.GetICMPxRejectCode(exprs.ICMP_NET_UNREACHABLE),
		},
		{
			"test-reject-icmpx-host-unreachable",
			fmt.Sprint("with icmpx ", exprs.ICMP_HOST_UNREACHABLE),
			exprs.NFT_FAMILY_INET,
			exprs.NFT_PROTO_ICMPX,
			unix.NFT_REJECT_ICMPX_UNREACH,
			exprs.GetICMPxRejectCode(exprs.ICMP_HOST_UNREACHABLE),
		},
		{
			"test-reject-icmpx-prot-unreachable",
			fmt.Sprint("with icmpx ", exprs.ICMP_PROT_UNREACHABLE),
			exprs.NFT_FAMILY_INET,
			exprs.NFT_PROTO_ICMPX,
			unix.NFT_REJECT_ICMPX_UNREACH,
			exprs.GetICMPxRejectCode(exprs.ICMP_PROT_UNREACHABLE),
		},
		{
			"test-reject-icmpx-port-unreachable",
			fmt.Sprint("with icmpx ", exprs.ICMP_PORT_UNREACHABLE),
			exprs.NFT_FAMILY_INET,
			exprs.NFT_PROTO_ICMPX,
			unix.NFT_REJECT_ICMPX_UNREACH,
			exprs.GetICMPxRejectCode(exprs.ICMP_PORT_UNREACHABLE),
		},
		{
			"test-reject-icmpx-no-route",
			fmt.Sprint("with icmpx ", exprs.ICMP_NO_ROUTE),
			exprs.NFT_FAMILY_INET,
			exprs.NFT_PROTO_ICMPX,
			unix.NFT_REJECT_ICMPX_UNREACH,
			exprs.GetICMPxRejectCode(exprs.ICMP_NO_ROUTE),
		},

		// icmpv6
		{
			"test-reject-icmpv6-net-unreachable",
			fmt.Sprint("with icmpv6 ", exprs.ICMP_NET_UNREACHABLE),
			exprs.NFT_FAMILY_IP6,
			exprs.NFT_PROTO_ICMPv6,
			1,
			exprs.GetICMPv6RejectCode(exprs.ICMP_NET_UNREACHABLE),
		},
		{
			"test-reject-icmpv6-addr-unreachable",
			fmt.Sprint("with icmpv6 ", exprs.ICMP_ADDR_UNREACHABLE),
			exprs.NFT_FAMILY_IP6,
			exprs.NFT_PROTO_ICMPv6,
			1,
			exprs.GetICMPv6RejectCode(exprs.ICMP_ADDR_UNREACHABLE),
		},
		{
			"test-reject-icmpv6-host-unreachable",
			fmt.Sprint("with icmpv6 ", exprs.ICMP_HOST_UNREACHABLE),
			exprs.NFT_FAMILY_IP6,
			exprs.NFT_PROTO_ICMPv6,
			1,
			exprs.GetICMPv6RejectCode(exprs.ICMP_HOST_UNREACHABLE),
		},
		{
			"test-reject-icmpv6-port-unreachable",
			fmt.Sprint("with icmpv6 ", exprs.ICMP_PORT_UNREACHABLE),
			exprs.NFT_FAMILY_IP6,
			exprs.NFT_PROTO_ICMPv6,
			1,
			exprs.GetICMPv6RejectCode(exprs.ICMP_PORT_UNREACHABLE),
		},
		{
			"test-reject-icmpv6-no-route",
			fmt.Sprint("with icmpv6 ", exprs.ICMP_NO_ROUTE),
			exprs.NFT_FAMILY_IP6,
			exprs.NFT_PROTO_ICMPv6,
			1,
			exprs.GetICMPv6RejectCode(exprs.ICMP_NO_ROUTE),
		},
		{
			"test-reject-icmpv6-reject-policy-fail",
			fmt.Sprint("with icmpv6 ", exprs.ICMP_REJECT_POLICY_FAIL),
			exprs.NFT_FAMILY_IP6,
			exprs.NFT_PROTO_ICMPv6,
			1,
			exprs.GetICMPv6RejectCode(exprs.ICMP_REJECT_POLICY_FAIL),
		},
		{
			"test-reject-icmpv6-reject-route",
			fmt.Sprint("with icmpv6 ", exprs.ICMP_REJECT_ROUTE),
			exprs.NFT_FAMILY_IP6,
			exprs.NFT_PROTO_ICMPv6,
			1,
			exprs.GetICMPv6RejectCode(exprs.ICMP_REJECT_ROUTE),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verdExpr := exprs.NewExprVerdict(exprs.VERDICT_REJECT, test.parms)
			r, _ := nftest.AddTestRule(t, conn, verdExpr)
			if r == nil {
				t.Errorf("Error adding rule with reject verdict %s", "")
				return
			}
			e := r.Exprs[0]
			if reflect.TypeOf(e).String() != "*expr.Reject" {
				t.Errorf("first expression should be *expr.Verdict, instead of: %s", reflect.TypeOf(e))
				return
			}
			verd, ok := e.(*expr.Reject)
			if !ok {
				t.Errorf("invalid verdict: %T", e)
				return
			}
			//fmt.Printf("reject verd: %+v\n", verd)

			if verd.Code != uint8(test.parmCode) {
				t.Errorf("invalid reject verdict code: %d, expected: %d", verd.Code, test.parmCode)
			}

		})
	}
}

func TestExprVerdictQueue(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	verdExpr := exprs.NewExprVerdict(exprs.VERDICT_QUEUE, "num 1")
	r, _ := nftest.AddTestRule(t, conn, verdExpr)
	if r == nil {
		t.Errorf("Error adding rule with Queue verdict")
		return
	}
	e := r.Exprs[0]
	if reflect.TypeOf(e).String() != "*expr.Queue" {
		t.Errorf("first expression should be *expr.Queue, instead of: %s", reflect.TypeOf(e))
		return
	}
	verd, ok := e.(*expr.Queue)
	if !ok {
		t.Errorf("invalid verdict: %T", e)
		return
	}
	if verd.Num != 1 {
		t.Errorf("invalid queue verdict Num: %d", verd.Num)
	}

}
