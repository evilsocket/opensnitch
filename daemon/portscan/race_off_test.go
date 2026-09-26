//go:build !race

package portscan

// raceEnabled reports whether the race detector is instrumenting this build.
//
// Timing assertions are meaningless under it: every memory access goes through
// the detector, which costs an order of magnitude. A test that measures a
// budget must say so rather than fail on the instrumentation.
const raceEnabled = false
