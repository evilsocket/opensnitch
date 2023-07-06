package exprs

import "github.com/google/nftables/expr"

// NewNoTrack adds a new expression not to track connections.
func NewNoTrack() *[]expr.Any {
	return &[]expr.Any{
		&expr.Notrack{},
	}
}
