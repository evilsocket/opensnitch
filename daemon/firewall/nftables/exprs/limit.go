package exprs

import (
	"fmt"
	"strconv"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/google/nftables/expr"
)

// NewExprLimit returns a new limit expression.
// limit rate [over] 1/second
// to express bytes units, we use: 10-mbytes instead of nft's 10 mbytes
func NewExprLimit(statement *config.ExprStatement) (*[]expr.Any, error) {
	var err error
	exprLimit := &expr.Limit{
		Type: expr.LimitTypePkts,
		Over: false,
		Unit: expr.LimitTimeSecond,
	}

	for _, values := range statement.Values {
		switch values.Key {

		case NFT_LIMIT_OVER:
			exprLimit.Over = true

		case NFT_LIMIT_UNITS:
			exprLimit.Rate, err = strconv.ParseUint(values.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("Invalid limit rate: %s", values.Value)
			}

		case NFT_LIMIT_BURST:
			limitBurst := 0
			limitBurst, err = strconv.Atoi(values.Value)
			if err != nil || limitBurst == 0 {
				return nil, fmt.Errorf("Invalid burst limit: %s, err: %s", values.Value, err)
			}
			exprLimit.Burst = uint32(limitBurst)

		case NFT_LIMIT_UNITS_RATE:
			// units rate must be placed AFTER the rate
			exprLimit.Type, exprLimit.Rate = getLimitRate(values.Value, exprLimit.Rate)

		case NFT_LIMIT_UNITS_TIME:
			exprLimit.Unit = getLimitUnits(values.Value)
		}
	}

	return &[]expr.Any{exprLimit}, nil
}

func getLimitUnits(units string) (limitUnits expr.LimitTime) {
	switch units {
	case NFT_LIMIT_UNIT_MINUTE:
		limitUnits = expr.LimitTimeMinute
	case NFT_LIMIT_UNIT_HOUR:
		limitUnits = expr.LimitTimeHour
	case NFT_LIMIT_UNIT_DAY:
		limitUnits = expr.LimitTimeDay
	default:
		limitUnits = expr.LimitTimeSecond
	}

	return limitUnits
}

func getLimitRate(units string, rate uint64) (limitType expr.LimitType, limitRate uint64) {
	switch units {
	case NFT_LIMIT_UNIT_KBYTES:
		limitRate = rate * 1024
		limitType = expr.LimitTypePktBytes
	case NFT_LIMIT_UNIT_MBYTES:
		limitRate = (rate * 1024) * 1024
		limitType = expr.LimitTypePktBytes
	default:
		limitType = expr.LimitTypePkts
		limitRate, _ = strconv.ParseUint(units, 10, 64)
	}

	return
}
