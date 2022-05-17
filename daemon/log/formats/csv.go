package formats

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

// CSV name of the output format, used in json configs
const CSV = "csv"

// Csv object
type Csv struct {
}

// NewCSV returns a new CSV transformer object.
func NewCSV() *Csv {
	return &Csv{}
}

// Transform takes input arguments and formats them to CSV.
func (c *Csv) Transform(args ...interface{}) (out string) {
	p := args[0]
	values := p.([]interface{})
	for _, val := range values {
		switch val.(type) {
		case *protocol.Connection:
			con := val.(*protocol.Connection)
			out = fmt.Sprint(out,
				con.SrcIp, ",",
				con.SrcPort, ",",
				con.DstIp, ",",
				con.DstHost, ",",
				con.DstPort, ",",
				con.Protocol, ",",
				con.ProcessId, ",",
				con.UserId, ",",
				//con.ProcessComm, ",",
				con.ProcessPath, ",",
				con.ProcessArgs, ",",
				con.ProcessCwd, ",",
			)
		default:
			out = fmt.Sprint(out, val, ",")
		}
	}
	out = out[:len(out)-1]

	return
}
