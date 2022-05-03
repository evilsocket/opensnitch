package exprs

import (
	"github.com/google/nftables/expr"
)

// NewExprCounter returns a counter for packets or bytes.
func NewExprCounter(counterName string) *[]expr.Any {
	return &[]expr.Any{
		&expr.Objref{
			Type: 1,
			Name: counterName,
		},
	}
}
