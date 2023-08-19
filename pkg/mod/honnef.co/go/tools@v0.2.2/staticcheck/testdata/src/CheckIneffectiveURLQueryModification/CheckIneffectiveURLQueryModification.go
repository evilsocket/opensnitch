package pkg

import "net/url"

func fn(u *url.URL) {
	u.Query().Add("", "") // want `returns a copy`
	u.Query().Set("", "") // want `returns a copy`
	u.Query().Del("")     // want `returns a copy`
	u.Query().Encode()

	var t T
	t.Query().Add("", "")
}

type T struct{}

func (v T) Query() T              { return v }
func (v T) Add(arg1, arg2 string) {}
