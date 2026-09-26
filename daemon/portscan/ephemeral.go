//go:build linux

package portscan

import (
	"os"
	"strconv"
	"strings"
	"sync"
)

// ephemeralRange is this host's local port range, as the kernel hands it out
// for outbound connections.
//
// The connection table is a snapshot rebuilt every ten seconds, so the SYN|ACK
// that opens a connection this host asked for often arrives before the
// connection is in it -- on a new ephemeral port every time, which
// deduplication cannot absorb, and ordinary traffic to one peer would cross the
// threshold. Which side chose the port decides: return traffic arrives at a
// port this host picked, a scan at ports the scanner picked. An ACK-bearing
// packet aimed at the ephemeral range with nothing listening is therefore not
// counted; everywhere else it is.
//
// The cost: an ACK scan confined to the ephemeral range is not detected. That
// is the direction this feature must err in; the worst it can do is cut the
// host off from something it needs.
func ephemeralRange() (lo, hi uint16) {
	ephemeralOnce.Do(func() {
		ephemeralLo, ephemeralHi = 32768, 60999 // the kernel's own defaults
		b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
		if err != nil {
			return
		}
		f := strings.Fields(string(b))
		if len(f) != 2 {
			return
		}
		l, err1 := strconv.ParseUint(f[0], 10, 16)
		h, err2 := strconv.ParseUint(f[1], 10, 16)
		if err1 != nil || err2 != nil || l == 0 || h < l {
			return
		}
		ephemeralLo, ephemeralHi = uint16(l), uint16(h)
	})
	return ephemeralLo, ephemeralHi
}

var (
	ephemeralOnce            sync.Once
	ephemeralLo, ephemeralHi uint16
)

// isEphemeralPort reports whether port is one the kernel would have chosen for
// an outbound connection of ours.
func isEphemeralPort(port uint16) bool {
	lo, hi := ephemeralRange()
	return port >= lo && port <= hi
}
