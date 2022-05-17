package formats

import (
	"fmt"

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
	p := args[0]
	values := p.([]interface{})
	for n, val := range values {
		switch val.(type) {
		case *protocol.Connection:
			con := val.(*protocol.Connection)
			out = fmt.Sprint(out,
				" SRC=\"", con.SrcIp, "\"",
				" SPT=\"", con.SrcPort, "\"",
				" DST=\"", con.DstIp, "\"",
				" DSTHOST=\"", con.DstHost, "\"",
				" DPT=\"", con.DstPort, "\"",
				" PROTO=\"", con.Protocol, "\"",
				" PID=\"", con.ProcessId, "\"",
				" UID=\"", con.UserId, "\"",
				//" COMM=", con.ProcessComm, "\"",
				" PATH=\"", con.ProcessPath, "\"",
				" CMDLINE=\"", con.ProcessArgs, "\"",
				" CWD=\"", con.ProcessCwd, "\"",
			)
		default:
			out = fmt.Sprint(out, " ARG", n, "=\"", val, "\"")
		}
	}
	out = fmt.Sprint("[", out[1:], "]")

	return
}
