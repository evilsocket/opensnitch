package formats

import (
	"log/syslog"
	"os"
	"strconv"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
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

// transform protocol.Connection to Structured Data format.
func connToSD(out string, val interface{}) string {
	checksums := ""
	tree := ""
	con := val.(*protocol.Connection)

	for k, v := range con.ProcessChecksums {
		checksums = core.ConcatStrings(checksums, k, ":", v)
	}
	for _, y := range con.ProcessTree {
		tree = core.ConcatStrings(tree, y.Key, ",")
	}

	// TODO: allow to configure this via configuration file.
	return core.ConcatStrings(out,
		" SRC=\"", con.SrcIp, "\"",
		" SPT=\"", strconv.FormatUint(uint64(con.SrcPort), 10), "\"",
		" DST=\"", con.DstIp, "\"",
		" DSTHOST=\"", con.DstHost, "\"",
		" DPT=\"", strconv.FormatUint(uint64(con.DstPort), 10), "\"",
		" PROTO=\"", con.Protocol, "\"",
		" PID=\"", strconv.FormatUint(uint64(con.ProcessId), 10), "\"",
		" UID=\"", strconv.FormatUint(uint64(con.UserId), 10), "\"",
		//" COMM=", con.ProcessComm, "\"",
		" PATH=\"", con.ProcessPath, "\"",
		" CMDLINE=\"", strings.Join(con.ProcessArgs, " "), "\"",
		" CWD=\"", con.ProcessCwd, "\"",
		" CHECKSUMS=\"", checksums, "\"",
		" PROCTREE=\"", tree, "\"",
		// TODO: envs
	)
}
