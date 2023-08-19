package tag

import (
	"log"
	"strconv"
	"time"

	"github.com/BurntSushi/toml/internal"
)

// Rempve JSON tags to a data structure as returned by toml-test.
func Remove(typedJson interface{}) interface{} {
	// Switch on the data type.
	switch v := typedJson.(type) {

	// Object: this can either be a TOML table or a primitive with tags.
	case map[string]interface{}:
		// This value represents a primitive: remove the tags and return just
		// the primitive value.
		if len(v) == 2 && in("type", v) && in("value", v) {
			return untag(v)
		}

		// Table: remove tags on all children.
		m := make(map[string]interface{}, len(v))
		for k, v2 := range v {
			m[k] = Remove(v2)
		}
		return m

	// Array: remove tags from all itenm.
	case []interface{}:
		a := make([]interface{}, len(v))
		for i := range v {
			a[i] = Remove(v[i])
		}
		return a
	}

	// The top level must be an object or array.
	log.Fatalf("Unrecognized JSON format '%T'.", typedJson)
	panic("unreachable")
}

// Check if key is in the table m.
func in(key string, m map[string]interface{}) bool {
	_, ok := m[key]
	return ok
}

// Return a primitive: read the "type" and convert the "value" to that.
func untag(typed map[string]interface{}) interface{} {
	t := typed["type"].(string)
	v := typed["value"].(string)
	switch t {
	case "string":
		return v
	case "integer":
		n, err := strconv.Atoi(v)
		if err != nil {
			log.Fatalf("Could not parse '%s' as integer: %s", v, err)
		}
		return n
	case "float":
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			log.Fatalf("Could not parse '%s' as float64: %s", v, err)
		}
		return f
	case "datetime":
		return parseTime(v, "2006-01-02T15:04:05.999999999Z07:00", nil)
	case "datetime-local":
		return parseTime(v, "2006-01-02T15:04:05.999999999", internal.LocalDatetime)
	case "date-local":
		return parseTime(v, "2006-01-02", internal.LocalDate)
	case "time-local":
		return parseTime(v, "15:04:05.999999999", internal.LocalTime)
	case "bool":
		switch v {
		case "true":
			return true
		case "false":
			return false
		}
		log.Fatalf("Could not parse '%s' as a boolean.", v)
	}

	log.Fatalf("Unrecognized tag type '%s'.", t)
	panic("unreachable")
}

func parseTime(v, format string, l *time.Location) time.Time {
	t, err := time.Parse(format, v)
	if err != nil {
		log.Fatalf("Could not parse '%s' as a datetime: %s", v, err)
	}
	if l != nil {
		t = t.In(l)
	}
	return t
}
