package pkg

import "strconv"

func fn() {
	strconv.ParseFloat("", 16) // want `'bitSize' argument is invalid, must be either 32 or 64`
	strconv.ParseFloat("", 32)
	strconv.ParseFloat("", 64)
	strconv.ParseFloat("", 128) // want `'bitSize' argument is invalid, must be either 32 or 64`

	strconv.ParseInt("", 0, -1) // want `'bitSize' argument is invalid, must be within 0 and 64`
	strconv.ParseInt("", 0, 0)
	strconv.ParseInt("", 0, 1)
	strconv.ParseInt("", 0, 64)
	strconv.ParseInt("", 0, 65) // want `'bitSize' argument is invalid, must be within 0 and 64`
	strconv.ParseInt("", -1, 0) // want `'base' must not be smaller than 2, unless it is 0`
	strconv.ParseInt("", 1, 0)  // want `'base' must not be smaller than 2, unless it is 0`
	strconv.ParseInt("", 2, 0)
	strconv.ParseInt("", 10, 0)
	strconv.ParseInt("", 36, 0)
	strconv.ParseInt("", 37, 0) // want `'base' must not be larger than 36`

	strconv.ParseUint("", 0, -1) // want `'bitSize' argument is invalid, must be within 0 and 64`
	strconv.ParseUint("", 0, 0)
	strconv.ParseUint("", 0, 1)
	strconv.ParseUint("", 0, 64)
	strconv.ParseUint("", 0, 65) // want `'bitSize' argument is invalid, must be within 0 and 64`
	strconv.ParseUint("", -1, 0) // want `'base' must not be smaller than 2, unless it is 0`
	strconv.ParseUint("", 1, 0)  // want `'base' must not be smaller than 2, unless it is 0`
	strconv.ParseUint("", 2, 0)
	strconv.ParseUint("", 10, 0)
	strconv.ParseUint("", 36, 0)
	strconv.ParseUint("", 37, 0) // want `'base' must not be larger than 36`

	strconv.FormatFloat(0, 'e', 0, 18) // want `'bitSize' argument is invalid, must be either 32 or 64`
	strconv.FormatFloat(0, 'e', 0, 32)
	strconv.FormatFloat(0, 'e', 0, 64)
	strconv.FormatFloat(0, 'e', 0, 128) // want `'bitSize' argument is invalid, must be either 32 or 64`
	strconv.FormatFloat(0, 'j', 0, 32)  // want `'fmt' argument is invalid: unknown format 'j'`

	strconv.FormatInt(0, 0) // want `'base' must not be smaller than 2`
	strconv.FormatInt(0, 1) // want `'base' must not be smaller than 2`
	strconv.FormatInt(0, 2)
	strconv.FormatInt(0, 3)
	strconv.FormatInt(0, 36)
	strconv.FormatInt(0, 37) // want `'base' must not be larger than 36`

	strconv.FormatUint(0, 0) // want `'base' must not be smaller than 2`
	strconv.FormatUint(0, 1) // want `'base' must not be smaller than 2`
	strconv.FormatUint(0, 2)
	strconv.FormatUint(0, 3)
	strconv.FormatUint(0, 36)
	strconv.FormatUint(0, 37) // want `'base' must not be larger than 36`

	strconv.AppendFloat(nil, 0, 'e', 0, 18) // want `'bitSize' argument is invalid, must be either 32 or 64`
	strconv.AppendFloat(nil, 0, 'e', 0, 32)
	strconv.AppendFloat(nil, 0, 'e', 0, 64)
	strconv.AppendFloat(nil, 0, 'e', 0, 128) // want `'bitSize' argument is invalid, must be either 32 or 64`
	strconv.AppendFloat(nil, 0, 'j', 0, 32)  // want `'fmt' argument is invalid: unknown format 'j'`

	strconv.AppendInt(nil, 0, 0) // want `'base' must not be smaller than 2`
	strconv.AppendInt(nil, 0, 1) // want `'base' must not be smaller than 2`
	strconv.AppendInt(nil, 0, 2)
	strconv.AppendInt(nil, 0, 3)
	strconv.AppendInt(nil, 0, 36)
	strconv.AppendInt(nil, 0, 37) // want `'base' must not be larger than 36`

	strconv.AppendUint(nil, 0, 0) // want `'base' must not be smaller than 2`
	strconv.AppendUint(nil, 0, 1) // want `'base' must not be smaller than 2`
	strconv.AppendUint(nil, 0, 2)
	strconv.AppendUint(nil, 0, 3)
	strconv.AppendUint(nil, 0, 36)
	strconv.AppendUint(nil, 0, 37) // want `'base' must not be larger than 36`
}
