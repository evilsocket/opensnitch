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

// RFC5424 name of the output format, used in our json config
const RFC5424 = "rfc5424"

// Rfc5424 object
type Rfc5424 struct {
	seq int
}

// NewRfc5424 returns a new Rfc5424 object, that transforms a message to
// RFC5424 format (sort of).
func NewRfc5424() *Rfc5424 {
	return &Rfc5424{}
}

// Transform takes input arguments and formats them to RFC5424 format.
func (r *Rfc5424) Transform(args ...interface{}) (out string) {
	hostname := ""
	tag := ""
	arg1 := args[0]
	if len(args) > 1 {
		arg2 := args[1]
		arg3 := args[2]
		hostname = arg2.(string)
		tag = arg3.(string)
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
	out = fmt.Sprintf("<%d>1 %s %s %s %d TCPOUT - [%s]\n",
		syslog.LOG_NOTICE|syslog.LOG_DAEMON,
		time.Now().Format(time.RFC3339),
		hostname,
		tag,
		os.Getpid(),
		out[1:])

	return
}
