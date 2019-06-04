package netstat

import (
	"net"
	"strings"
	
	"github.com/evilsocket/opensnitch/daemon/log"
)

func FindEntry(proto string, srcIP net.IP, srcPort uint, dstIP net.IP, dstPort uint) *Entry {
	if entry := findEntryForProtocol(proto, srcIP, srcPort, dstIP, dstPort); entry != nil {
		return entry
	}

	ipv6Suffix := "6"
	if strings.HasSuffix(proto, ipv6Suffix) == false {
		otherProto := proto + ipv6Suffix
		log.Debug("Searching for %s netstat entry instead of %s", otherProto, proto)
		return findEntryForProtocol(otherProto, srcIP, srcPort, dstIP, dstPort)
	}
	
	return nil;
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
