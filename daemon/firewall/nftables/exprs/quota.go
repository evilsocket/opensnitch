package exprs

import (
	"fmt"
	"strconv"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/google/nftables/expr"
)

// NewQuota returns a new quota expression.
// TODO: named quotas
func NewQuota(opts []*config.ExprValues) (*[]expr.Any, error) {
	over := false
	bytes := int64(0)
	used := int64(0)
	for _, opt := range opts {
		switch opt.Key {
		case NFT_QUOTA_OVER:
			over = true
		case NFT_QUOTA_UNIT_BYTES:
			b, err := strconv.ParseInt(opt.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid quota bytes: %s", opt.Value)
			}
			bytes = b
		case NFT_QUOTA_USED:
			// TODO: support for other size units
			b, err := strconv.ParseInt(opt.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid quota initial consumed bytes: %s", opt.Value)
			}
			used = b
		case NFT_QUOTA_UNIT_KB:
			b, err := strconv.ParseInt(opt.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid quota bytes: %s", opt.Value)
			}
			bytes = b * 1024
		case NFT_QUOTA_UNIT_MB:
			b, err := strconv.ParseInt(opt.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid quota bytes: %s", opt.Value)
			}
			bytes = (b * 1024) * 1024
		case NFT_QUOTA_UNIT_GB:
			b, err := strconv.ParseInt(opt.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid quota bytes: %s", opt.Value)
			}
			bytes = ((b * 1024) * 1024) * 1024
		default:
			return nil, fmt.Errorf("invalid quota key: %s", opt.Key)
		}
	}
	if bytes == 0 {
		return nil, fmt.Errorf("quota bytes cannot be 0")
	}
	return &[]expr.Any{
		&expr.Quota{
			Bytes:    uint64(bytes),
			Consumed: uint64(used),
			Over:     over,
		},
	}, nil
}
