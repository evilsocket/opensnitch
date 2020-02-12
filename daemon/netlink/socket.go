package netlink

import (
    "syscall"
    "net"

    "github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
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
    } else if proto[:3] == "tcp" {
        srcAddr := &net.TCPAddr{ IP: srcIP, Port: int(srcPort), }
        dstAddr := &net.TCPAddr{ IP: dstIP, Port: int(dstPort), }
        s, err = SocketGet(family, ipproto, srcAddr, dstAddr)
    } else {
        log.Debug("Unknown protocol, not implemented", proto)
        return -1, -1
    }
    if err == nil && s.INode > 0 && s.INode != 0xffffffff {
        if s.UID == 0xffffffff {
            return -1, int(s.INode)
        }
        return int(s.UID), int(s.INode)
    } else if err != nil {
        log.Debug("Netlink socket error", err)
    }

    return -1, -1
}
