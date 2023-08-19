package pkg

import (
	"bytes"
	"strings"
)

func fn() {
	strings.Replace("", "", "", -1) // want `could use strings.ReplaceAll instead`
	strings.Replace("", "", "", 0)
	strings.Replace("", "", "", 1)

	strings.SplitN("", "", -1) // want `could use strings.Split instead`
	strings.SplitN("", "", 0)
	strings.SplitN("", "", 1)

	strings.SplitAfterN("", "", -1) // want `could use strings.SplitAfter instead`
	strings.SplitAfterN("", "", 0)
	strings.SplitAfterN("", "", 1)

	bytes.Replace(nil, nil, nil, -1) // want `could use bytes.ReplaceAll instead`
	bytes.Replace(nil, nil, nil, 0)
	bytes.Replace(nil, nil, nil, 1)

	bytes.SplitN(nil, nil, -1) // want `could use bytes.Split instead`
	bytes.SplitN(nil, nil, 0)
	bytes.SplitN(nil, nil, 1)

	bytes.SplitAfterN(nil, nil, -1) // want `could use bytes.SplitAfter instead`
	bytes.SplitAfterN(nil, nil, 0)
	bytes.SplitAfterN(nil, nil, 1)
}
