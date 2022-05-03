package exprs

import (
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// NewExprLog returns a new log expression.
func NewExprLog(what, options string) *[]expr.Any {
	exprLog := []expr.Any{}

	options += " "
	switch what {
	case NFT_LOG_PREFIX:
		exprLog = append(exprLog, []expr.Any{
			&expr.Log{
				Key:  1 << unix.NFTA_LOG_PREFIX,
				Data: []byte(options),
			},
		}...)
	// TODO
	//case exprs.NFT_LOG_LEVEL:
	//case exprs.NFT_LOG_FLAGS:
	default:
		return nil
	}

	return &exprLog
}
