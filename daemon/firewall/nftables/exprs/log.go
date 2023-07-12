package exprs

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// NewExprLog returns a new log expression.
func NewExprLog(statement *config.ExprStatement) (*[]expr.Any, error) {
	prefix := "opensnitch"
	logExpr := expr.Log{
		Key:  1 << unix.NFTA_LOG_PREFIX,
		Data: []byte(prefix),
	}

	for _, values := range statement.Values {
		switch values.Key {
		case NFT_LOG_PREFIX:
			if values.Value == "" {
				return nil, fmt.Errorf("Invalid log prefix, it's empty")
			}
			logExpr.Data = []byte(values.Value)
		case NFT_LOG_LEVEL:
			lvl, err := getLogLevel(values.Value)
			if err != nil {
				log.Warning("%s", err)
				return nil, err
			}
			logExpr.Key |= 1 << unix.NFTA_LOG_LEVEL
			logExpr.Level = lvl
			// TODO
			// https://github.com/google/nftables/blob/main/nftables_test.go#L623
			//case exprs.NFT_LOG_FLAGS:
			//case exprs.NFT_LOG_GROUP:
			//case exprs.NFT_LOG_QTHRESHOLD:
		}
	}

	return &[]expr.Any{
		&logExpr,
	}, nil

}

func getLogLevel(what string) (expr.LogLevel, error) {
	switch what {
	// https://github.com/google/nftables/blob/main/expr/log.go#L28
	case NFT_LOG_LEVEL_EMERG:
		return expr.LogLevelEmerg, nil
	case NFT_LOG_LEVEL_ALERT:
		return expr.LogLevelAlert, nil
	case NFT_LOG_LEVEL_CRIT:
		return expr.LogLevelCrit, nil
	case NFT_LOG_LEVEL_ERR:
		return expr.LogLevelErr, nil
	case NFT_LOG_LEVEL_WARN:
		return expr.LogLevelWarning, nil
	case NFT_LOG_LEVEL_NOTICE:
		return expr.LogLevelNotice, nil
	case NFT_LOG_LEVEL_INFO:
		return expr.LogLevelInfo, nil
	case NFT_LOG_LEVEL_DEBUG:
		return expr.LogLevelDebug, nil
	case NFT_LOG_LEVEL_AUDIT:
		return expr.LogLevelAudit, nil
	}

	return 0, fmt.Errorf("Invalid log level: %s", what)
}
