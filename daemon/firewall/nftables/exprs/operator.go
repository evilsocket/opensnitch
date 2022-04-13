package exprs

import (
	"github.com/google/nftables/expr"
)

// NewOperator translates a string comparator operator to nftables operator
func NewOperator(operator string) expr.CmpOp {
	switch operator {
	case "!=":
		return expr.CmpOpNeq
	case ">":
		return expr.CmpOpGt
	case ">=":
		return expr.CmpOpGte
	case "<":
		return expr.CmpOpLt
	case "<=":
		return expr.CmpOpLte
	}

	return expr.CmpOpEq
}

// NewExprOperator returns a new comparator operator
func NewExprOperator(op expr.CmpOp) *[]expr.Any {
	return &[]expr.Any{
		&expr.Cmp{
			Register: 1,
			Op:       op,
		},
	}
}
