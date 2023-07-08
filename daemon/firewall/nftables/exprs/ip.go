package exprs

import (
	"fmt"
	"net"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// NewExprIP returns a new IP expression.
// You can use multiple statements to specify daddr + saddr, or combine them
// in a single statement expression:
// Example 1 (filtering by source and dest address):
// "Name": "ip",
// "Values": [ {"Key": "saddr": "Value": "1.2.3.4"},{"Key": "daddr": "Value": "1.2.3.5"} ]
// Example 2 (filtering by multiple dest addrs IPs):
// "Name": "ip",
// "Values": [
//   {"Key": "daddr": "Value": "1.2.3.4"},
//   {"Key": "daddr": "Value": "1.2.3.5"}
// ]
// Example 3 (filtering by network range):
// "Name": "ip",
// "Values": [
//   {"Key": "daddr": "Value": "1.2.3.4-1.2.9.254"}
// ]
// TODO (filter by multiple dest addrs separated by commas):
// "Values": [
//   {"Key": "daddr": "Value": "1.2.3.4,1.2.9.254"}
// ]
func NewExprIP(family string, ipOptions []*config.ExprValues, cmpOp expr.CmpOp) (*[]expr.Any, error) {
	var exprIP []expr.Any

	// if the table family is inet, we need to specify the protocol of the IP being added.
	if family == NFT_FAMILY_INET {
		exprIP = append(exprIP, &expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1})
		exprIP = append(exprIP, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}})
	}
	for _, ipOpt := range ipOptions {
		// TODO: ipv6
		switch ipOpt.Key {
		case NFT_SADDR, NFT_DADDR:
			payload := getExprIPPayload(ipOpt.Key)
			exprIP = append(exprIP, payload)
			if strings.Index(ipOpt.Value, "-") == -1 {
				exprIPtemp, err := getExprIP(ipOpt.Value, cmpOp)
				if err != nil {
					return nil, err
				}
				exprIP = append(exprIP, *exprIPtemp...)
			} else {
				exprIPtemp, err := getExprRangeIP(ipOpt.Value, cmpOp)
				if err != nil {
					return nil, err
				}
				exprIP = append(exprIP, *exprIPtemp...)
			}

		case NFT_PROTOCOL:
			payload := getExprIPPayload(ipOpt.Key)
			exprIP = append(exprIP, payload)
			protoCode, err := getProtocolCode(ipOpt.Value)
			if err != nil {
				return nil, err
			}
			exprIP = append(exprIP, []expr.Any{
				&expr.Cmp{
					Op:       cmpOp,
					Register: 1,
					Data:     []byte{byte(protoCode)},
				},
			}...)
		}
	}
	return &exprIP, nil
}

func getExprIPPayload(what string) *expr.Payload {

	switch what {
	case NFT_PROTOCOL:
		return &expr.Payload{
			DestRegister: 1,
			Offset:       9, // daddr
			Base:         expr.PayloadBaseNetworkHeader,
			Len:          1, // 16 ipv6
		}
	case NFT_DADDR:
		// NOTE 1: if "what" is daddr and SourceRegister is part of the Payload{} expression,
		// the rule is not added.
		return &expr.Payload{
			DestRegister: 1,
			Offset:       16, // daddr
			Base:         expr.PayloadBaseNetworkHeader,
			Len:          4, // 16 ipv6
		}

	default:
		return &expr.Payload{
			SourceRegister: 1,
			DestRegister:   1,
			Offset:         12, // saddr
			Base:           expr.PayloadBaseNetworkHeader,
			Len:            4, // 16 ipv6
		}
	}
}

// Supported IP types: a.b.c.d, a.b.c.d-w.x.y.z
// TODO: support IPs separated by commas: a.b.c.d, e.f.g.h,...
func getExprIP(value string, cmpOp expr.CmpOp) (*[]expr.Any, error) {
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("Invalid IP: %s", value)
	}

	return &[]expr.Any{
		&expr.Cmp{
			Op:       cmpOp,
			Register: 1,
			Data:     ip.To4(),
		},
	}, nil
}

// Supported IP types: a.b.c.d, a.b.c.d-w.x.y.z
// TODO: support IPs separated by commas: a.b.c.d, e.f.g.h,...
func getExprRangeIP(value string, cmpOp expr.CmpOp) (*[]expr.Any, error) {
	ips := strings.Split(value, "-")
	ipSrc := net.ParseIP(ips[0])
	ipDst := net.ParseIP(ips[1])
	if ipSrc == nil || ipDst == nil {
		return nil, fmt.Errorf("Invalid IPs range: %v", ips)
	}

	return &[]expr.Any{
		&expr.Range{
			Op:       cmpOp,
			Register: 1,
			FromData: ipSrc.To4(),
			ToData:   ipDst.To4(),
		},
	}, nil
}
