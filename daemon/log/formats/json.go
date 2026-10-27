package formats

import (
	"encoding/json"

	"github.com/evilsocket/opensnitch/daemon/core"
	taskBase "github.com/evilsocket/opensnitch/daemon/tasks/base"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"google.golang.org/protobuf/proto"
)

// JSON name of the output format, used in our json config
const JSON = "json"

// events types
const (
	EvConnection = iota
	EvExec
	EvTaskNotification
)

// JSONEventFormat object to be sent to the remote service.
// TODO: Expand as needed: ebpf events, etc.
type JSONEventFormat struct {
	Event  interface{} `json:"Event"`
	Rule   string      `json:"Rule"`
	Action string      `json:"Action"`
	Type   uint8       `json:"Type"`

	// includeProcessEnv adds the environment variables of the process to
	// the connection events. They may contain secrets (tokens, passwords),
	// so they're not sent by default.
	includeProcessEnv bool
}

// NewJSON returns a new Json format, to send events as json.
// The json is the protobuffer in json format.
func NewJSON(includeProcessEnv bool) *JSONEventFormat {
	return &JSONEventFormat{includeProcessEnv: includeProcessEnv}
}

// Transform takes input arguments and formats them to JSON format.
func (j *JSONEventFormat) Transform(args ...interface{}) (out string) {
	p := args[0]
	jObj := &JSONEventFormat{}

	values := p.([]interface{})
	for n, val := range values {
		switch val.(type) {
		// TODO:
		// case *protocol.Rule:
		// case *protocol.Process:
		// case *protocol.Alerts:
		case *protocol.Connection:
			// XXX: All fields of the Connection object are sent, is this what we want?
			// or should we send an anonymous json?
			con := val.(*protocol.Connection)
			if !j.includeProcessEnv && len(con.ProcessEnv) > 0 {
				// the Connection object is shared with other loggers and
				// the env map with the process, so don't modify it.
				con = proto.Clone(con).(*protocol.Connection)
				con.ProcessEnv = nil
			}
			jObj.Event = con
			jObj.Type = EvConnection

		case taskBase.TaskNotification:
			jObj.Event = val.(taskBase.TaskNotification)
			jObj.Type = EvTaskNotification

		case string:
			// action
			// rule name
			if n == 1 {
				jObj.Action = val.(string)
			} else if n == 2 {
				jObj.Rule = val.(string)
			}
		}
	}

	rawCfg, err := json.Marshal(&jObj)
	if err != nil {
		return
	}
	out = core.ConcatStrings(string(rawCfg), "\n\n")
	return
}
