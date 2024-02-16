package exprs

import (
	"strconv"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/log"
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
		var err error
		p := strings.Split(parms, " ")
		if len(p) == 0 {
			log.Warning("invalid Queue expr parameters")
			return nil
		}
		// TODO: allow to configure this flag
		if p[0] == NFT_QUEUE_NUM {
			queueNum, err = strconv.Atoi(p[len(p)-1])
			if err != nil {
				log.Warning("invalid Queue num: %s", err)
				return nil
			}
		}

		return &[]expr.Any{
			&expr.Queue{
				Num:  uint16(queueNum),
				Flag: expr.QueueFlagBypass,
			}}

	case VERDICT_SNAT:
		snat := NewExprSNAT()
		snat.Random, snat.FullyRandom, snat.Persistent = NewExprNATFlags(parms)
		snatExpr := &[]expr.Any{snat}

		regAddr, regProto, natParms, err := NewExprNAT(parms, VERDICT_SNAT)
		if err != nil {
			log.Warning("error adding snat verdict: %s", err)
			return nil
		}
		if regAddr {
			snat.RegAddrMin = 1
		}
		if regProto {
			snat.RegProtoMin = 2
		}
		*snatExpr = append(*natParms, *snatExpr...)
		return snatExpr

	case VERDICT_DNAT:
		dnat := NewExprDNAT()
		dnat.Random, dnat.FullyRandom, dnat.Persistent = NewExprNATFlags(parms)
		dnatExpr := &[]expr.Any{dnat}

		regAddr, regProto, natParms, err := NewExprNAT(parms, VERDICT_DNAT)
		if err != nil {
			log.Warning("error adding dnat verdict: %s", err)
			return nil
		}

		if regAddr {
			dnat.RegAddrMin = 1
		}
		if regProto {
			dnat.RegProtoMin = 2
		}
		*dnatExpr = append(*natParms, *dnatExpr...)

		return dnatExpr

	case VERDICT_MASQUERADE:
		m := &expr.Masq{}
		m.Random, m.FullyRandom, m.Persistent = NewExprNATFlags(parms)
		masqExpr := &[]expr.Any{m}

		if parms == "" {
			return masqExpr
		}
		// if any of the flag is set to true, toPorts must be false
		toPorts := !(m.Random == true || m.FullyRandom == true || m.Persistent == true)
		masqExpr = NewExprMasquerade(toPorts, m.Random, m.FullyRandom, m.Persistent)
		_, _, natParms, err := NewExprNAT(parms, VERDICT_MASQUERADE)
		if err != nil {
			log.Warning("error adding masquerade verdict: %s", err)
		}
		*masqExpr = append(*natParms, *masqExpr...)

		return masqExpr

	case VERDICT_REDIRECT:
		_, _, rewriteParms, err := NewExprNAT(parms, VERDICT_REDIRECT)
		if err != nil {
			log.Warning("error adding redirect verdict: %s", err)
			return nil
		}
		redirExpr := NewExprRedirect()
		*redirExpr = append(*rewriteParms, *redirExpr...)
		return redirExpr

	case VERDICT_TPROXY:
		_, _, rewriteParms, err := NewExprNAT(parms, VERDICT_TPROXY)
		if err != nil {
			log.Warning("error adding tproxy verdict: %s", err)
			return nil
		}
		tproxyExpr := &[]expr.Any{}
		*tproxyExpr = append(*tproxyExpr, *rewriteParms...)
		tVerdict := NewExprTproxy()
		*tproxyExpr = append(*tproxyExpr, *tVerdict...)
		*tproxyExpr = append(*tproxyExpr, *NewExprAccept()...)
		return tproxyExpr

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
		reject.Code = GetICMPRejectCode(how)
		return reject
	case NFT_PROTO_ICMPX:
		// icmp and icmpv6
		reject.Type = unix.NFT_REJECT_ICMPX_UNREACH
		reject.Code = GetICMPxRejectCode(how)
		return reject
	case NFT_PROTO_ICMPv6:
		reject.Type = 1
		reject.Code = GetICMPv6RejectCode(how)

	default:
	}

	return reject
}
