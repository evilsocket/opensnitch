package exprs

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// NewExprProtocol creates a new expression to filter connections by protocol
func NewExprProtocol(proto string) (*[]expr.Any, error) {
	switch strings.ToLower(proto) {
	case NFT_PROTO_UDP:
		return &[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
		}, nil

	case NFT_PROTO_TCP:
		return &[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
		}, nil

	case NFT_PROTO_UDPLITE:
		return &[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDPLITE},
			},
		}, nil

	case NFT_PROTO_SCTP:
		return &[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_SCTP},
			},
		}, nil

	case NFT_PROTO_DCCP:
		return &[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_DCCP},
			},
		}, nil

	case NFT_PROTO_ICMP:
		return &[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_ICMP},
			},
		}, nil

	default:
		return nil, fmt.Errorf("Not valid protocol rule, invalid or not supported protocol: %s", proto)
	}

}
