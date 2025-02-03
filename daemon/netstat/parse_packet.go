package netstat

import (
	"bufio"
	"os"
	"regexp"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
)

var (
	// sk               RefCnt Type Proto  Iface R Rmem   User   Inode
	// ffff90b72f893800 3      3    0003   3     1 0      0      257944535
	packetParser = regexp.MustCompile(`(?i)` +
		`[a-z0-9]+\s+` + // sk
		`[0-9]\s+` + // refCnt
		`([0-9])\s+` + // Type
		`([0-9a-z]+)\s+` + // proto
		`([0-9])\s+` + // iface
		`[0-9]\s+` + // r
		`[0-9]+\s+` + // rmem
		`([0-9]+)\s+` + // user
		`([0-9]+)`, // inode
	)
)

// ParsePacket scans and retrieves the opened sockets from /proc/net/packet
func ParsePacket() ([]Entry, error) {
	filename := core.ConcatStrings("/proc/net/packet")
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	entries := make([]Entry, 0)
	scanner := bufio.NewScanner(fd)
	for lineno := 0; scanner.Scan(); lineno++ {
		// skip column names
		if lineno == 0 {
			continue
		}

		line := core.Trim(scanner.Text())
		m := packetParser.FindStringSubmatch(line)
		if m == nil {
			log.Warning("Could not parse netstat line from %s: %s", filename, line)
			continue
		}
		// TODO: get proto, type, etc.
		en := Entry{}
		en.Iface = decToInt(m[3])
		en.UserId = decToInt(m[4])
		en.INode = decToInt(m[5])

		entries = append(entries, en)
	}

	return entries, nil
}
