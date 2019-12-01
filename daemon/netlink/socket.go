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

    var s *Socket
    var err error
    if proto[:3] == "udp" {
        ipproto = syscall.IPPROTO_UDP
        if protoLen >=7 && proto[:7] == "udplite" {
            ipproto = syscall.IPPROTO_UDPLITE
        }
        srcAddr := &net.UDPAddr{ IP: srcIP, Port: int(srcPort), }
        dstAddr := &net.UDPAddr{ IP: dstIP, Port: int(dstPort), }
        s, err = SocketGet(family, ipproto, srcAddr, dstAddr)
    } else {
        srcAddr := &net.TCPAddr{ IP: srcIP, Port: int(srcPort), }
        dstAddr := &net.TCPAddr{ IP: dstIP, Port: int(dstPort), }
        s, err = SocketGet(family, ipproto, srcAddr, dstAddr)
    }
    if err == nil && s.INode != 0xffffffff {
        return int(s.UID), int(s.INode)
    }

    return -1, -1
}
