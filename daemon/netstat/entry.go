package netstat

import (
	"net"
)

type Entry struct {
	Proto   string
	SrcIP   net.IP
	SrcPort uint
	DstIP   net.IP
	DstPort uint
	UserId  int
	INode   int
}

func NewEntry(proto string, srcIP net.IP, srcPort uint, dstIP net.IP, dstPort uint, userId int, iNode int) Entry {
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
