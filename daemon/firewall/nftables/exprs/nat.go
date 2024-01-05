package exprs

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// NewExprNATFlags returns the nat flags configured.
// common to masquerade, snat and dnat
func NewExprNATFlags(parms string) (random, fullrandom, persistent bool) {
	masqParms := strings.Split(parms, ",")
	for _, mParm := range masqParms {
		switch mParm {
		case NFT_MASQ_RANDOM:
			random = true
		case NFT_MASQ_FULLY_RANDOM:
			fullrandom = true
		case NFT_MASQ_PERSISTENT:
			persistent = true
		}
	}

	return
}

// NewExprNAT parses the redirection of redirect, snat, dnat, tproxy and masquerade verdict:
// to x.y.z.a:abcd
// If only the IP is specified (to 1.2.3.4), only NAT.RegAddrMin must be present (regAddr == true)
// If only the port is specified (to :1234), only NAT.RegPortMin must be present (regPort == true)
// If both addr and port are specified (to 1.2.3.4:1234), NAT.RegPortMin and NAT.RegAddrMin must be present.
func NewExprNAT(parms, verdict string) (bool, bool, *[]expr.Any, error) {
	regAddr := false
	regProto := false
	exprNAT := []expr.Any{}
	NATParms := strings.Split(parms, " ")

	idx := 0
	// exclude first parameter if it's "to"
	if NATParms[idx] == NFT_PARM_TO {
		idx++
	}
	if idx == len(NATParms) {
		return regAddr, regProto, &exprNAT, fmt.Errorf("Invalid parms: %s", parms)
	}

	dParms := strings.Split(NATParms[idx], ":")
	// masquerade doesn't allow "to IP"
	if dParms[0] != "" && verdict != VERDICT_MASQUERADE {
		dIP := dParms[0]
		destIP := net.ParseIP(dIP)
		if destIP == nil {
			return regAddr, regProto, &exprNAT, fmt.Errorf("Invalid IP: %s", dIP)
		}

		exprNAT = append(exprNAT, []expr.Any{
			&expr.Immediate{
				Register: 1,
				Data:     destIP.To4(),
			}}...)
		regAddr = true
	}

	if len(dParms) == 2 {
		dPort := dParms[1]
		// TODO: support ranges. 9000-9100
		destPort, err := strconv.Atoi(dPort)
		if err != nil {
			return regAddr, regProto, &exprNAT, fmt.Errorf("Invalid Port: %s", dPort)
		}
		reg := uint32(2)
		toPort := binaryutil.BigEndian.PutUint16(uint16(destPort))
		// if reg=1 (RegAddrMin=1) is not set, this error appears listing the rules
		// "netlink: Error: NAT statement has no proto expression"
		if verdict == VERDICT_TPROXY || verdict == VERDICT_MASQUERADE || verdict == VERDICT_REDIRECT {
			// according to https://github.com/google/nftables/blob/8a10f689006bf728a5cff35787713047f68e308a/nftables_test.go#L4871
			// Masquerade ports should be specified like this:
			// toPort = binaryutil.BigEndian.PutUint32(uint32(destPort) << 16)
			// but then it's not added/listed correctly with nft.

			reg = 1
		}
		exprNAT = append(exprNAT, []expr.Any{
			&expr.Immediate{
				Register: reg,
				Data:     toPort,
			}}...)
		regProto = true
	}

	return regAddr, regProto, &exprNAT, nil
}

// NewExprMasquerade returns a new masquerade expression.
func NewExprMasquerade(toPorts, random, fullRandom, persistent bool) *[]expr.Any {
	exprMasq := &expr.Masq{
		ToPorts:     toPorts,
		Random:      random,
		FullyRandom: fullRandom,
		Persistent:  persistent,
	}
	if toPorts {
		exprMasq.RegProtoMin = 1
	}
	return &[]expr.Any{
		exprMasq,
	}
}

// NewExprRedirect returns a new redirect expression.
func NewExprRedirect() *[]expr.Any {
	return &[]expr.Any{
		// Redirect is a special case of DNAT where the destination is the current machine
		&expr.Redir{
			RegisterProtoMin: 1,
		},
	}
}

// NewExprSNAT returns a new snat expression.
func NewExprSNAT() *expr.NAT {
	return &expr.NAT{
		Type:   expr.NATTypeSourceNAT,
		Family: unix.NFPROTO_IPV4,
	}
}

// NewExprDNAT returns a new dnat expression.
func NewExprDNAT() *expr.NAT {
	return &expr.NAT{
		Type:   expr.NATTypeDestNAT,
		Family: unix.NFPROTO_IPV4,
	}
}

// NewExprTproxy returns a new tproxy expression.
// XXX: is "to x.x.x.x:1234" supported by google/nftables lib? or only "to :1234"?
// it creates an erronous rule.
func NewExprTproxy() *[]expr.Any {
	return &[]expr.Any{
		&expr.TProxy{
			Family:      byte(nftables.TableFamilyIPv4),
			TableFamily: byte(nftables.TableFamilyIPv4),
			RegPort:     1,
		}}
}
