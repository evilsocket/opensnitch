// +build gofuzzbeta

package toml

import (
	"bytes"
	"testing"
)

func FuzzDecode(f *testing.F) {
	buf := make([]byte, 0, 2048)

	f.Add(`
# This is a TOML document

title = "TOML Example"

[owner]
name = "Tom Preston-Werner"
dob = 1979-05-27T07:32:00-08:00

[database]
enabled = true
ports = [ 8000, 8001, 8002 ]
data = [ ["delta", "phi"], [3.14] ]
temp_targets = { cpu = 79.5, case = 72.0 }

[servers]

[servers.alpha]
ip = "10.0.0.1"
role = "frontend"

[servers.beta]
ip = "10.0.0.2"
role = "backend"
`)
	f.Fuzz(func(t *testing.T, file string) {
		var m map[string]interface{}
		_, err := Decode(file, &m)
		if err != nil {
			t.Skip()
		}

		NewEncoder(bytes.NewBuffer(buf)).Encode(m)

		// TODO: should check if the output is equal to the input, too, but some
		// information is lost when encoding.
	})
}
