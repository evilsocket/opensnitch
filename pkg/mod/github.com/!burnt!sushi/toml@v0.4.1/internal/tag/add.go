package tag

import (
	"fmt"
	"math"
	"time"

	"github.com/BurntSushi/toml/internal"
)

// Add JSON tags to a data structure as expected by toml-test.
func Add(key string, tomlData interface{}) interface{} {
	// Switch on the data type.
	switch orig := tomlData.(type) {
	default:
		panic(fmt.Sprintf("Unknown type: %T", tomlData))

	// A table: we don't need to add any tags, just recurse for every table
	// entry.
	case map[string]interface{}:
		typed := make(map[string]interface{}, len(orig))
		for k, v := range orig {
			typed[k] = Add(k, v)
		}
		return typed

	// An array: we don't need to add any tags, just recurse for every table
	// entry.
	case []map[string]interface{}:
		typed := make([]map[string]interface{}, len(orig))
		for i, v := range orig {
			typed[i] = Add("", v).(map[string]interface{})
		}
		return typed
	case []interface{}:
		typed := make([]interface{}, len(orig))
		for i, v := range orig {
			typed[i] = Add("", v)
		}
		return typed

	// Datetime: tag as datetime.
	case time.Time:
		switch orig.Location() {
		default:
			return tag("datetime", orig.Format("2006-01-02T15:04:05.999999999Z07:00"))
		case internal.LocalDatetime:
			return tag("datetime-local", orig.Format("2006-01-02T15:04:05.999999999"))
		case internal.LocalDate:
			return tag("date-local", orig.Format("2006-01-02"))
		case internal.LocalTime:
			return tag("time-local", orig.Format("15:04:05.999999999"))
		}

	// Tag primitive values: bool, string, int, and float64.
	case bool:
		return tag("bool", fmt.Sprintf("%v", orig))
	case string:
		return tag("string", orig)
	case int64:
		return tag("integer", fmt.Sprintf("%d", orig))
	case float64:
		// Special case for nan since NaN == NaN is false.
		if math.IsNaN(orig) {
			return tag("float", "nan")
		}
		return tag("float", fmt.Sprintf("%v", orig))
	}
}

func tag(typeName string, data interface{}) map[string]interface{} {
	return map[string]interface{}{
		"type":  typeName,
		"value": data,
	}
}
