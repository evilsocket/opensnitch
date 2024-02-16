package formats

import (
	"encoding/json"
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

// JSON name of the output format, used in our json config
const JSON = "json"

// events types
const (
	EvConnection = iota
	EvExec
)

// JSONEventFormat object to be sent to the remote service.
// TODO: Expand as needed: ebpf events, etc.
type JSONEventFormat struct {
	Event  interface{} `json:"Event"`
	Rule   string      `json:"Rule"`
	Action string      `json:"Action"`
	Type   uint8       `json:"Type"`
}

// NewJSON returns a new Json format, to send events as json.
// The json is the protobuffer in json format.
func NewJSON() *JSONEventFormat {
	return &JSONEventFormat{}
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
			jObj.Event = val.(*protocol.Connection)
			jObj.Type = EvConnection

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
	out = fmt.Sprint(string(rawCfg), "\n\n")
	return
}
