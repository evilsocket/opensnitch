package exprs

import (
	"fmt"
	"strconv"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// NewExprMeta creates a new meta selector to match or set packet metainformation.
// https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
func NewExprMeta(values []*config.ExprValues) (*[]expr.Any, error) {
	setValue := false
	metaExpr := []expr.Any{}

	for _, meta := range values {
		switch meta.Key {
		case NFT_META_SET_MARK:
			setValue = true
			continue

		case NFT_META_MARK:
			mark, err := getMetaValue(meta.Value)
			if err != nil {
				return nil, err
			}
			if setValue {
				metaExpr = append(metaExpr, []expr.Any{
					&expr.Immediate{
						Register: 1,
						Data:     binaryutil.NativeEndian.PutUint32(uint32(mark)),
					}}...)
			}
			metaExpr = append(metaExpr, []expr.Any{
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(uint32(mark)),
				}}...)
			return &metaExpr, nil

		case NFT_META_PRIORITY:
			mark, err := getMetaValue(meta.Value)
			if err != nil {
				return nil, err
			}
			if setValue {
				metaExpr = append(metaExpr, []expr.Any{
					&expr.Immediate{
						Register: 1,
						Data:     binaryutil.NativeEndian.PutUint32(uint32(mark)),
					}}...)
			}
			return &[]expr.Any{
				&expr.Meta{Key: expr.MetaKeyPRIORITY, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(uint32(mark)),
				},
			}, nil
		case NFT_META_NFTRACE:
			mark, err := getMetaValue(meta.Value)
			if err != nil {
				return nil, err
			}
			if mark != 0 && mark != 1 {
				return nil, fmt.Errorf("%s Invalid nftrace value: %d. Only 1 or 0 allowed", "nftables", mark)
			}
			// TODO: not working yet
			return &[]expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFTRACE, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(uint32(mark)),
				},
			}, nil

		default:
			// not supported yet
		}
	}

	return nil, fmt.Errorf("%s meta keyword not supported yet, open a new issue on github", "nftables")
}

func getMetaValue(value string) (int, error) {
	metaVal, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return metaVal, nil
}
