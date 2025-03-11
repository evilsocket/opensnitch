package formats

import (
	"log/syslog"
	"os"
	"strconv"
)

// LoggerFormat is the common interface that every format must meet.
// Transform expects an arbitrary number of arguments and types, and
// it must transform them to a string.
// Arguments can be of type Connection, string, int, etc.
type LoggerFormat interface {
	Transform(...interface{}) string
}

var (
	ourPid      = ""
	syslogLevel = ""
)

func init() {
	ourPid = strconv.FormatUint(uint64(os.Getpid()), 10)
	syslogLevel = strconv.FormatUint(uint64(syslog.LOG_NOTICE|syslog.LOG_DAEMON), 10)
}
