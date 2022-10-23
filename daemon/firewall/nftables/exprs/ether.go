package exprs

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/google/nftables/expr"
)

// NewExprEther creates a new expression to match ethernet MAC addresses
func NewExprEther(values []*config.ExprValues) (*[]expr.Any, error) {
	etherExpr := []expr.Any{}
	macDir := uint32(6)

	for _, eth := range values {
		if eth.Key == NFT_DADDR {
			macDir = uint32(0)
		} else {
			macDir = uint32(6)
		}
		macaddr, err := parseMACAddr(eth.Value)
		if err != nil {
			return nil, err
		}
		etherExpr = append(etherExpr, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFTYPE, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x01, 0x00},
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseLLHeader,
				Offset:       macDir,
				Len:          6,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     macaddr,
			},
		}...)
	}
	return &etherExpr, nil
}

func parseMACAddr(macValue string) ([]byte, error) {
	mac := strings.Split(macValue, ":")
	macaddr := make([]byte, 0)
	if len(mac) != 6 {
		return nil, fmt.Errorf("Invalid MAC address: %s", macValue)
	}
	for i, m := range mac {
		mm, err := hex.DecodeString(m)
		if err != nil {
			return nil, fmt.Errorf("Invalid MAC byte: %c (%s)", mm[i], macValue)
		}
		macaddr = append(macaddr, mm[0])
	}
	return macaddr, nil
}
