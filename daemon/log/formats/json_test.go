package formats

import (
	"encoding/json"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

func newTestConnection() *protocol.Connection {
	return &protocol.Connection{
		Protocol:    "tcp",
		SrcIp:       "127.0.0.1",
		SrcPort:     44444,
		DstIp:       "1.1.1.1",
		DstHost:     "one.one.one.one",
		DstPort:     443,
		UserId:      1000,
		ProcessId:   1234,
		ProcessPath: "/usr/bin/curl",
		ProcessArgs: []string{"curl", "https://one.one.one.one"},
		ProcessEnv: map[string]string{
			"HOME":      "/home/user",
			"API_TOKEN": "secret",
		},
	}
}

func transformConnection(t *testing.T, jf *JSONEventFormat, con *protocol.Connection) map[string]interface{} {
	out := jf.Transform([]interface{}{con, "allow", "000-allow-curl"})
	if out == "" {
		t.Fatal("Transform() returned an empty string")
	}

	var ev struct {
		Event  map[string]interface{}
		Rule   string
		Action string
		Type   uint8
	}
	if err := json.Unmarshal([]byte(out), &ev); err != nil {
		t.Fatalf("Transform() returned invalid json: %s, %s", err, out)
	}
	if ev.Action != "allow" || ev.Rule != "000-allow-curl" || ev.Type != EvConnection {
		t.Errorf("unexpected event fields: %+v", ev)
	}
	if ev.Event["process_path"] != "/usr/bin/curl" {
		t.Errorf("process_path not sent: %v", ev.Event)
	}

	return ev.Event
}

func TestJSONProcessEnv(t *testing.T) {
	t.Run("process env omitted by default", func(t *testing.T) {
		con := newTestConnection()
		ev := transformConnection(t, NewJSON(false), con)
		if _, found := ev["process_env"]; found {
			t.Errorf("process_env should not be sent by default: %v", ev["process_env"])
		}
		if _, found := ev["process_args"]; !found {
			t.Error("process_args should be sent")
		}
	})

	t.Run("original connection not modified", func(t *testing.T) {
		con := newTestConnection()
		transformConnection(t, NewJSON(false), con)
		if len(con.ProcessEnv) != 2 || con.ProcessEnv["API_TOKEN"] != "secret" {
			t.Errorf("Transform() modified the original connection: %v", con.ProcessEnv)
		}
	})

	t.Run("process env included if enabled", func(t *testing.T) {
		con := newTestConnection()
		ev := transformConnection(t, NewJSON(true), con)
		env, ok := ev["process_env"].(map[string]interface{})
		if !ok {
			t.Fatalf("process_env not sent: %v", ev)
		}
		if env["HOME"] != "/home/user" || env["API_TOKEN"] != "secret" {
			t.Errorf("unexpected process_env: %v", env)
		}
	})
}
