package exprs

import "github.com/google/nftables/expr"

func NewNoTrack() *[]expr.Any {
	return &[]expr.Any{
		&expr.Notrack{},
	}
}
