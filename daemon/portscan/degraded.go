//go:build linux

package portscan

import (
	"errors"
	"fmt"
)

// ErrDegraded marks an error meaning the feature runs with less protection
// than the configuration asked for, which the daemon shows the user. A sentinel
// rather than matching message text, which drifts: an error either wraps it or
// not, and a degradation left unmarked is visible at its call site.
var ErrDegraded = errors.New("portscan: running with less protection than configured")

// degraded builds an error that the daemon will surface to the user. Use it
// for anything that means the feature is not doing all it claims: no
// enforcement backend, an incomplete never-block list, a blind host view,
// dropped probes, blocks that could not be released, a fallback to a slower
// path. Per-packet noise is not a degradation. The format goes to fmt.Errorf,
// so callers keep %w for the error they wrap.
func degraded(format string, args ...interface{}) error {
	return fmt.Errorf("%w: "+format, append([]interface{}{ErrDegraded}, args...)...)
}

// IsDegradation reports whether err means the feature is running with less
// protection than configured.
func IsDegradation(err error) bool { return errors.Is(err, ErrDegraded) }
