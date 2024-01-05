package exprs

import (
	"fmt"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// NewExprProtocol creates a new expression to filter connections by protocol
func NewExprProtocol(proto string) (*[]expr.Any, error) {
	protoExpr := expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}

	switch strings.ToLower(proto) {
	case NFT_META_L4PROTO:
		return &[]expr.Any{
			&protoExpr,
		}, nil

	case NFT_PROTO_UDP:
		return &[]expr.Any{
			&protoExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
		}, nil

	case NFT_PROTO_TCP:
		return &[]expr.Any{
			&protoExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
		}, nil

	case NFT_PROTO_UDPLITE:
		return &[]expr.Any{
			&protoExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDPLITE},
			},
		}, nil

	case NFT_PROTO_SCTP:
		return &[]expr.Any{
			&protoExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_SCTP},
			},
		}, nil

	case NFT_PROTO_DCCP:
		return &[]expr.Any{
			&protoExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_DCCP},
			},
		}, nil

	case NFT_PROTO_ICMP:
		return &[]expr.Any{
			&protoExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_ICMP},
			},
		}, nil

	case NFT_PROTO_ICMPv6:
		return &[]expr.Any{
			&protoExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_ICMPV6},
			},
		}, nil

		/*TODO: could be simplified
		default:
		proto, err := getProtocolCode(value)
		if err != nil {
			return nil, err
		}
		return &[]expr.Any{
			protoExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(proto)},
			},
		}, nil
		*/
	default:
		return nil, fmt.Errorf("Not valid protocol rule, invalid or not supported protocol: %s", proto)
	}

}

// NewExprProtoSet creates a new list of SetElements{}, to match
// multiple protocol values.
func NewExprProtoSet(l4prots string) *[]nftables.SetElement {
	protoList := strings.Split(l4prots, ",")
	protoSet := []nftables.SetElement{}
	for _, name := range protoList {
		pcode, err := getProtocolCode(name)
		if err != nil {
			continue
		}

		protoSet = append(protoSet,
			[]nftables.SetElement{
				{Key: []byte{byte(pcode)}},
			}...)
	}

	return &protoSet
}

// NewExprL4Proto returns a new expression to match a protocol.
func NewExprL4Proto(name string, cmpOp *expr.CmpOp) *[]expr.Any {
	proto, _ := getProtocolCode(name)
	return &[]expr.Any{
		&expr.Cmp{
			Op:       *cmpOp,
			Register: 1,
			Data:     []byte{byte(proto)},
		},
	}
}
