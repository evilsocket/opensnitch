package pattern

import (
	"testing"
)

func TestParse(t *testing.T) {
	inputs := []string{
		`(Binding "name" _)`,
		`(Binding "name" _:[])`,
		`(Binding "name" _:_:[])`,
	}

	p := Parser{}
	for _, input := range inputs {
		if _, err := p.Parse(input); err != nil {
			t.Errorf("failed to parse %q: %s", input, err)
		}
	}
}
