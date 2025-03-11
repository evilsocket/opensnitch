package formats

import (
	"fmt"
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
	event := "GENERIC"
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
			tree := ""
			checksums := ""
			con := val.(*protocol.Connection)
			event = "CONNECTION"

			for k, v := range con.ProcessChecksums {
				checksums = core.ConcatStrings(checksums, k, ":", v)
			}
			for _, y := range con.ProcessTree {
				tree = core.ConcatStrings(tree, y.Key, ",")
			}

			// TODO: allow to configure this via configuration file.
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
				" CHECKSUMS=\"", checksums, "\"",
				" PROCTREE=\"", tree, "\"",
			)
		default:
			out = fmt.Sprint(out, " ARG", n, "=\"", val, "\"")
		}
	}
	out = fmt.Sprintf("<%s>1 %s %s %s %s %s - [%s]\n",
		syslogLevel,
		time.Now().Format(time.RFC3339),
		hostname,
		tag,
		ourPid,
		event,
		out[1:])

	return
}
