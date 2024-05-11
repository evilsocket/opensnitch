package formats

import (
	"fmt"
	"log/syslog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

// RFC3164 name of the output format, used in our json config
const RFC3164 = "rfc3164"

// Rfc3164 object
type Rfc3164 struct {
	seq int
}

// NewRfc3164 returns a new Rfc3164 object, that transforms a message to
// RFC3164 format.
func NewRfc3164() *Rfc3164 {
	return &Rfc3164{}
}

// Transform takes input arguments and formats them to RFC3164 format.
func (r *Rfc3164) Transform(args ...interface{}) (out string) {
	hostname := ""
	tag := ""
	arg1 := args[0]
	// we can do this better. Think.
	if len(args) > 1 {
		hostname = args[1].(string)
		tag = args[2].(string)
	}
	values := arg1.([]interface{})
	for n, val := range values {
		switch val.(type) {
		case *protocol.Connection:
			con := val.(*protocol.Connection)
			out = core.ConcatStrings(out,
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
			)
		default:
			out = fmt.Sprint(out, " ARG", n, "=\"", val, "\"")
		}
	}
	out = fmt.Sprintf("<%d>%s %s %s[%d]: [%s]\n",
		syslog.LOG_NOTICE|syslog.LOG_DAEMON,
		time.Now().Format(time.RFC3339),
		hostname,
		tag,
		os.Getpid(),
		out[1:])

	return
}
