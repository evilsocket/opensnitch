package formats

// LoggerFormat is the common interface that every format must meet.
// Transform expects an arbitrary number of arguments and types, and
// it must transform them to a string.
// Arguments can be of type Connection, string, int, etc.
type LoggerFormat interface {
	Transform(...interface{}) string
}
