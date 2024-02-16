package exprs

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// Example https://github.com/google/nftables/blob/master/nftables_test.go#L1234
// https://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_metainformation

// NewExprCtMark returns a new ct expression.
// # set
// # nft --debug netlink  add rule filter output mark set 1
// ip filter output
//  [ immediate reg 1 0x00000001 ]
//  [ meta set mark with reg 1 ]
//
// match mark:
// nft --debug netlink add rule mangle prerouting ct mark 123
// [ ct load mark => reg 1 ]
// [ cmp eq reg 1 0x0000007b ]
func NewExprCtMark(setMark bool, value string, cmpOp *expr.CmpOp) (*[]expr.Any, error) {
	mark, err := strconv.Atoi(value)
	if err != nil {
		return nil, fmt.Errorf("Invalid conntrack mark: %s (%s)", err, value)
	}

	exprCtMark := []expr.Any{}
	exprCtMark = append(exprCtMark, []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(uint32(mark)),
		},
		&expr.Ct{
			Key:            expr.CtKeyMARK,
			Register:       1,
			SourceRegister: setMark,
		},
	}...)
	if setMark == false {
		exprCtMark = append(exprCtMark, []expr.Any{
			&expr.Cmp{Op: *cmpOp, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(mark))},
		}...)
	}

	return &exprCtMark, nil
}

// NewExprCtState returns a new ct expression.
func NewExprCtState(ctFlags []*config.ExprValues) (*[]expr.Any, error) {
	mask := uint32(0)

	for _, flag := range ctFlags {
		found, msk, err := parseInlineCtStates(flag.Value)
		if err != nil {
			return nil, err
		}
		if found {
			mask |= msk
			continue
		}

		msk, err = getCtState(flag.Value)
		if err != nil {
			return nil, err
		}
		mask |= msk
	}

	return &[]expr.Any{
		&expr.Ct{
			Register: 1, SourceRegister: false, Key: expr.CtKeySTATE,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(mask),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
	}, nil
}

func parseInlineCtStates(flags string) (found bool, mask uint32, err error) {
	// a "state" flag may be compounded of multiple values, separated by commas:
	// related,established
	fgs := strings.Split(flags, ",")
	if len(fgs) > 0 {
		for _, fg := range fgs {
			msk, err := getCtState(fg)
			if err != nil {
				return false, 0, err
			}
			mask |= msk
			found = true
		}
	}
	return
}

func getCtState(flag string) (mask uint32, err error) {
	switch strings.ToLower(flag) {
	case CT_STATE_NEW:
		mask |= expr.CtStateBitNEW
	case CT_STATE_ESTABLISHED:
		mask |= expr.CtStateBitESTABLISHED
	case CT_STATE_RELATED:
		mask |= expr.CtStateBitRELATED
	case CT_STATE_INVALID:
		mask |= expr.CtStateBitINVALID
	default:
		return 0, fmt.Errorf("Invalid conntrack flag: %s", flag)
	}

	return
}
