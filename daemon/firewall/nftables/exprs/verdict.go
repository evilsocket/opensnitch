package exprs

import (
	"strconv"
	"strings"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// NewExprVerdict constructs a new verdict to apply on connections.
func NewExprVerdict(verdict, parms string) *[]expr.Any {
	switch strings.ToLower(verdict) {
	case VERDICT_ACCEPT:
		return NewExprAccept()

	case VERDICT_DROP:
		return &[]expr.Any{&expr.Verdict{
			Kind: expr.VerdictDrop,
		}}

	// FIXME: this verdict is not added to nftables
	case VERDICT_STOP:
		return &[]expr.Any{&expr.Verdict{
			Kind: expr.VerdictStop,
		}}

	case VERDICT_REJECT:
		reject := NewExprReject(parms)
		return &[]expr.Any{reject}

	case VERDICT_RETURN:
		return &[]expr.Any{&expr.Verdict{
			Kind: expr.VerdictReturn,
		}}

	case VERDICT_JUMP:
		return &[]expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictKind(unix.NFT_JUMP),
				Chain: parms,
			},
		}

	case VERDICT_QUEUE:
		queueNum := 0
		p := strings.Split(parms, " ")
		if len(p) > 0 {
			if p[0] == NFT_QUEUE_NUM {
				queueNum, _ = strconv.Atoi(p[len(p)-1])
			}
		}
		return &[]expr.Any{
			&expr.Queue{
				Num: uint16(queueNum),
				// TODO: allow to configure this flag
				Flag: expr.QueueFlagBypass,
			}}

	case VERDICT_SNAT:
		snat := NewExprSNAT()
		snat.Random, snat.FullyRandom, snat.Persistent = NewExprNATFlags(parms)
		snatExpr := &[]expr.Any{snat}

		if regAddr, regProto, natParms, err := NewExprNAT(parms, VERDICT_SNAT); err == nil {
			if regAddr {
				snat.RegAddrMin = 1
			}
			if regProto {
				snat.RegProtoMin = 2
			}
			*snatExpr = append(*natParms, *snatExpr...)
		}
		return snatExpr

	case VERDICT_DNAT:
		dnat := NewExprDNAT()
		dnat.Random, dnat.FullyRandom, dnat.Persistent = NewExprNATFlags(parms)
		dnatExpr := &[]expr.Any{dnat}

		if regAddr, regProto, natParms, err := NewExprNAT(parms, VERDICT_DNAT); err == nil {
			if regAddr {
				dnat.RegAddrMin = 1
			}
			if regProto {
				dnat.RegProtoMin = 2
			}
			*dnatExpr = append(*natParms, *dnatExpr...)
		}
		return dnatExpr

	case VERDICT_MASQUERADE:
		m := &expr.Masq{}
		m.Random, m.FullyRandom, m.Persistent = NewExprNATFlags(parms)
		masqExpr := &[]expr.Any{m}

		if _, _, natParms, err := NewExprNAT(parms, VERDICT_MASQUERADE); err == nil {
			masqExpr = NewExprMasquerade(true)
			*masqExpr = append(*natParms, *masqExpr...)
		}

		return masqExpr

	case VERDICT_REDIRECT:
		if _, _, rewriteParms, err := NewExprNAT(parms, VERDICT_REDIRECT); err == nil {
			redirExpr := NewExprRedirect()
			*redirExpr = append(*rewriteParms, *redirExpr...)
			return redirExpr
		}

	case VERDICT_TPROXY:
		if _, _, rewriteParms, err := NewExprNAT(parms, VERDICT_TPROXY); err == nil {
			tproxyExpr := &[]expr.Any{}
			*tproxyExpr = append(*tproxyExpr, *rewriteParms...)
			tVerdict := NewExprTproxy()
			*tproxyExpr = append(*tproxyExpr, *tVerdict...)
			*tproxyExpr = append(*tproxyExpr, *NewExprAccept()...)
			return tproxyExpr
		}
	}

	// target can be empty, "ct set mark" or "log" for example
	return &[]expr.Any{}
}

// NewExprAccept creates the accept verdict.
func NewExprAccept() *[]expr.Any {
	return &[]expr.Any{&expr.Verdict{
		Kind: expr.VerdictAccept,
	}}
}

// NewExprReject creates new Reject expression
// icmpx, to reject the IPv4 and IPv6 traffic, icmp for ipv4, icmpv6 for ...
// Ex.: "Target": "reject", "TargetParameters": "with tcp reset"
// https://wiki.nftables.org/wiki-nftables/index.php/Rejecting_traffic
func NewExprReject(parms string) *expr.Reject {
	reject := &expr.Reject{}
	reject.Code = unix.NFT_REJECT_ICMP_UNREACH
	reject.Type = unix.NFT_REJECT_ICMP_UNREACH

	parmList := strings.Split(parms, " ")
	length := len(parmList)
	if length <= 1 {
		return reject
	}
	what := parmList[1]
	how := parmList[length-1]

	switch what {
	case NFT_PROTO_TCP:
		reject.Type = unix.NFT_REJECT_TCP_RST
		reject.Code = unix.NFT_REJECT_TCP_RST
	case NFT_PROTO_ICMP:
		reject.Type = unix.NFT_REJECT_ICMP_UNREACH
		reject.Code = getICMPRejectCode(how)
		return reject
	case NFT_PROTO_ICMPX:
		// icmp and icmpv6
		reject.Type = unix.NFT_REJECT_ICMPX_UNREACH
		reject.Code = getICMPxRejectCode(how)
		return reject
	case NFT_PROTO_ICMPv6:
		reject.Type = 1
		reject.Code = getICMPv6RejectCode(how)

	default:
	}

	return reject
}
