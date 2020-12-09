package netstat

import (
	"net"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
)

// FindEntry looks for the connection in the list of known connections in ProcFS.
func FindEntry(proto string, srcIP net.IP, srcPort uint, dstIP net.IP, dstPort uint) *Entry {
	if entry := findEntryForProtocol(proto, srcIP, srcPort, dstIP, dstPort); entry != nil {
		return entry
	}

	ipv6Suffix := "6"
	if core.IPv6Enabled && strings.HasSuffix(proto, ipv6Suffix) == false {
		otherProto := proto + ipv6Suffix
		log.Debug("Searching for %s netstat entry instead of %s", otherProto, proto)
		if entry := findEntryForProtocol(otherProto, srcIP, srcPort, dstIP, dstPort); entry != nil {
			return entry
		}
	}

	return &Entry{
		Proto:   proto,
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   dstIP,
		DstPort: dstPort,
		UserId:  -1,
		INode:   -1,
	}
}

func findEntryForProtocol(proto string, srcIP net.IP, srcPort uint, dstIP net.IP, dstPort uint) *Entry {
	entries, err := Parse(proto)
	if err != nil {
		log.Warning("Error while searching for %s netstat entry: %s", proto, err)
		return nil
	}

	for _, entry := range entries {
		if srcIP.Equal(entry.SrcIP) && srcPort == entry.SrcPort && dstIP.Equal(entry.DstIP) && dstPort == entry.DstPort {
			return &entry
		}
	}

	return nil
}
