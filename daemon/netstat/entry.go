package netstat

import (
	"net"
)

type Entry struct {
	Proto   string
	SrcIP   net.IP
	SrcPort int
	DstIP   net.IP
	DstPort int
	UserId  int
	INode   int
}

func NewEntry(proto string, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, userId int, iNode int) Entry {
	return Entry{
		Proto:   proto,
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   dstIP,
		DstPort: dstPort,
		UserId:  userId,
		INode:   iNode,
	}
}
