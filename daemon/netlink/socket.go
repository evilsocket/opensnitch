package netlink

import (
	"syscall"
	"net"
)

func GetSocketInfo(proto string, srcIP net.IP, srcPort uint, dstIP net.IP, dstPort uint) (uid, inode int) {
	family := uint8(syscall.AF_INET)
	ipproto := uint8(syscall.IPPROTO_TCP)
	protoLen := len(proto)
	if proto[protoLen-1:protoLen] == "6" {
		family = syscall.AF_INET6
	}

	var err error
	if proto[:3] == "udp" {
		ipproto = syscall.IPPROTO_UDP
		if protoLen >=7 && proto[:7] == "udplite" {
			ipproto = syscall.IPPROTO_UDPLITE
		}
	}
    sock, err := SocketGet(family, ipproto, uint16(srcPort), uint16(dstPort), srcIP, dstIP)
	if err == nil && sock.INode > 0 && sock.INode != 0xffffffff {
		if sock.UID == 0xffffffff {
			return -1, int(sock.INode)
		}
		return int(sock.UID), int(sock.INode)
	}

	return -1, -1
}
