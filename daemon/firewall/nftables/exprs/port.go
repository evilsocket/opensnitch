package exprs

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// NewExprPort returns a new port expression with the given matching operator.
func NewExprPort(port string, op *expr.CmpOp) (*[]expr.Any, error) {
	eport, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	return &[]expr.Any{
		&expr.Cmp{
			Register: 1,
			Op:       *op,
			Data:     binaryutil.BigEndian.PutUint16(uint16(eport))},
	}, nil
}

// NewExprPortRange returns a new port range expression.
func NewExprPortRange(sport string, cmpOp *expr.CmpOp) (*[]expr.Any, error) {
	ports := strings.Split(sport, "-")
	iport, err := strconv.Atoi(ports[0])
	if err != nil {
		return nil, err
	}
	eport, err := strconv.Atoi(ports[1])
	if err != nil {
		return nil, err
	}
	return &[]expr.Any{
		&expr.Range{
			Op:       *cmpOp,
			Register: 1,
			FromData: binaryutil.BigEndian.PutUint16(uint16(iport)),
			ToData:   binaryutil.BigEndian.PutUint16(uint16(eport)),
		},
	}, nil

}

// NewExprPortSet returns a new set of ports.
func NewExprPortSet(portv string) *[]nftables.SetElement {
	setElements := []nftables.SetElement{}
	ports := strings.Split(portv, ",")
	for _, portv := range ports {
		portExpr := exprPortSubSet(portv)
		if portExpr != nil {
			setElements = append(setElements, *portExpr...)
		}
	}

	return &setElements
}

func exprPortSubSet(portv string) *[]nftables.SetElement {
	port, err := strconv.Atoi(portv)
	if err != nil {
		return nil
	}

	return &[]nftables.SetElement{
		{Key: binaryutil.BigEndian.PutUint16(uint16(port))},
	}

}

// NewExprPortDirection returns a new expression to match connections based on
// the direction of the connection (source, dest)
func NewExprPortDirection(direction string) (*expr.Payload, error) {
	switch direction {
	case NFT_DPORT:
		return &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		}, nil
	case NFT_SPORT:
		return &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       0,
			Len:          2,
		}, nil
	default:
		return nil, fmt.Errorf("Not valid protocol direction: %s", direction)
	}

}
