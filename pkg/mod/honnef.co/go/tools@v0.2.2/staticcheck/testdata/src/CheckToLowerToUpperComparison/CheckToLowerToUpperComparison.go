package pkg

import "strings"

func fn() {
	const (
		s1 = "foo"
		s2 = "bar"
	)

	if strings.ToLower(s1) == strings.ToLower(s2) { // want `should use strings\.EqualFold instead`
		panic("")
	}

	if strings.ToUpper(s1) == strings.ToUpper(s2) { // want `should use strings\.EqualFold instead`
		panic("")
	}

	if strings.ToLower(s1) != strings.ToLower(s2) { // want `should use strings\.EqualFold instead`
		panic("")
	}

	switch strings.ToLower(s1) == strings.ToLower(s2) { // want `should use strings\.EqualFold instead`
	case true, false:
		panic("")
	}

	if strings.ToLower(s1) == strings.ToLower(s2) || s1+s2 == s2+s1 { // want `should use strings\.EqualFold instead`
		panic("")
	}

	if strings.ToLower(s1) > strings.ToLower(s2) {
		panic("")
	}

	if strings.ToLower(s1) < strings.ToLower(s2) {
		panic("")
	}

	if strings.ToLower(s1) == strings.ToUpper(s2) {
		panic("")
	}
}
