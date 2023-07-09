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
func NewExprMeta(values []*config.ExprValues, cmpOp *expr.CmpOp) (*[]expr.Any, error) {
	setMark := false
	metaExpr := []expr.Any{}

	for _, meta := range values {
		switch meta.Key {
		case NFT_META_SET_MARK:
			setMark = true
			continue
		case NFT_META_MARK:
			metaKey, err := getMetaKey(meta.Key)
			if err != nil {
				return nil, err
			}
			metaVal, err := getMetaValue(meta.Value)
			if err != nil {
				return nil, err
			}
			if setMark {
				metaExpr = append(metaExpr, []expr.Any{
					&expr.Immediate{
						Register: 1,
						Data:     binaryutil.NativeEndian.PutUint32(uint32(metaVal)),
					}}...)
				metaExpr = append(metaExpr, []expr.Any{
					&expr.Meta{Key: metaKey, Register: 1, SourceRegister: setMark}}...)
			} else {
				metaExpr = append(metaExpr, []expr.Any{
					&expr.Meta{Key: metaKey, Register: 1, SourceRegister: setMark},
					&expr.Cmp{
						Op:       *cmpOp,
						Register: 1,
						Data:     binaryutil.NativeEndian.PutUint32(uint32(metaVal)),
					}}...)
			}

			setMark = false
			return &metaExpr, nil

		case NFT_META_L4PROTO:
			mexpr, err := NewExprProtocol(meta.Key)
			if err != nil {
				return nil, err
			}
			metaExpr = append(metaExpr, *mexpr...)

			return &metaExpr, nil

		case NFT_META_PRIORITY,
			NFT_META_SKUID, NFT_META_SKGID,
			NFT_META_PROTOCOL:

			metaKey, err := getMetaKey(meta.Key)
			if err != nil {
				return nil, err
			}
			metaVal, err := getProtocolCode(meta.Value)
			if err != nil {
				return nil, err
			}
			metaExpr = append(metaExpr, []expr.Any{
				&expr.Meta{Key: metaKey, Register: 1, SourceRegister: setMark},
				&expr.Cmp{
					Op:       *cmpOp,
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(uint32(metaVal)),
				}}...)

			setMark = false
			return &metaExpr, nil

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
					Op:       *cmpOp,
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

// https://github.com/google/nftables/blob/main/expr/expr.go#L168
func getMetaKey(value string) (expr.MetaKey, error) {
	switch value {
	case NFT_META_MARK:
		return expr.MetaKeyMARK, nil
	case NFT_META_PRIORITY:
		return expr.MetaKeyPRIORITY, nil
	case NFT_META_SKUID:
		return expr.MetaKeySKUID, nil
	case NFT_META_SKGID:
		return expr.MetaKeySKGID, nil
	// ip, ip6, arp, vlan
	case NFT_META_PROTOCOL:
		return expr.MetaKeyPROTOCOL, nil
	case NFT_META_L4PROTO:
		return expr.MetaKeyL4PROTO, nil
	}

	return expr.MetaKeyPRANDOM, fmt.Errorf("meta key %s not supported (yet)", value)
}
