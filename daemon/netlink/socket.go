package netlink

import (
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/evilsocket/opensnitch/daemon/log"
)

// GetSocketInfo asks the kernel via netlink for a given connection.
// If the connection is found, we return the uid and the possible
// associated inodes.
// If the outgoing connection is not found but there're entries with the source
// port and same protocol, add all the inodes to the list.
//
// Some examples:
// outgoing connection as seen by netfilter || connection details dumped from kernel
//
// 47344:192.168.1.106 -> 151.101.65.140:443 || in kernel: 47344:192.168.1.106 -> 151.101.65.140:443
// 8612:192.168.1.5 -> 192.168.1.255:8612  || in kernel: 8612:192.168.1.105 -> 0.0.0.0:0
// 123:192.168.1.5  -> 217.144.138.234:123 || in kernel: 123:0.0.0.0 -> 0.0.0.0:0
// 45015:127.0.0.1 -> 239.255.255.250:1900 || in kernel: 45015:127.0.0.1 -> 0.0.0.0:0
// 50416:fe80::9fc2:ddcf:df22:aa50 -> fe80::1:53 || in kernel: 50416:254.128.0.0 -> 254.128.0.0:53
// 51413:192.168.1.106 -> 103.224.182.250:1337 || in kernel: 51413:0.0.0.0 -> 0.0.0.0:0
func GetSocketInfo(proto string, srcIP net.IP, srcPort uint, dstIP net.IP, dstPort uint) (uid int, inodes []int) {
	uid = -1
	family := uint8(syscall.AF_INET)
	ipproto := uint8(syscall.IPPROTO_TCP)
	protoLen := len(proto)
	if proto[protoLen-1:protoLen] == "6" {
		family = syscall.AF_INET6
	}

	if proto[:3] == "udp" {
		ipproto = syscall.IPPROTO_UDP
		if protoLen >= 7 && proto[:7] == "udplite" {
			ipproto = syscall.IPPROTO_UDPLITE
		}
	}
	if sockList, err := SocketGet(family, ipproto, uint16(srcPort), uint16(dstPort), srcIP, dstIP); err == nil {
		for n, sock := range sockList {
			if sock.UID != 0xffffffff {
				uid = int(sock.UID)
			}
			log.Debug("[%d/%d] outgoing connection: %d:%v -> %v:%d || netlink response: %d:%v -> %v:%d inode: %d - loopback: %v multicast: %v unspecified: %v linklocalunicast: %v ifaceLocalMulticast: %v GlobalUni: %v ",
				n, len(sockList),
				srcPort, srcIP, dstIP, dstPort,
				sock.ID.SourcePort, sock.ID.Source,
				sock.ID.Destination, sock.ID.DestinationPort, sock.INode,
				sock.ID.Destination.IsLoopback(),
				sock.ID.Destination.IsMulticast(),
				sock.ID.Destination.IsUnspecified(),
				sock.ID.Destination.IsLinkLocalUnicast(),
				sock.ID.Destination.IsLinkLocalMulticast(),
				sock.ID.Destination.IsGlobalUnicast(),
			)

			if sock.ID.SourcePort == uint16(srcPort) && sock.ID.Source.Equal(srcIP) &&
				(sock.ID.DestinationPort == uint16(dstPort)) &&
				((sock.ID.Destination.IsGlobalUnicast() || sock.ID.Destination.IsLoopback()) && sock.ID.Destination.Equal(dstIP)) {
				inodes = append([]int{int(sock.INode)}, inodes...)
				continue
			} else if sock.ID.SourcePort == uint16(srcPort) && sock.ID.Source.Equal(srcIP) &&
				(sock.ID.DestinationPort == uint16(dstPort)) {
				inodes = append([]int{int(sock.INode)}, inodes...)
				continue
			}
			log.Debug("GetSocketInfo() invalid: %d:%v -> %v:%d", sock.ID.SourcePort, sock.ID.Source, sock.ID.Destination, sock.ID.DestinationPort)
		}

		if len(inodes) == 0 && len(sockList) > 0 {
			for n, sock := range sockList {
				if sockList[n].ID.Destination.Equal(net.IPv4zero) || sockList[n].ID.Destination.Equal(net.IPv6zero) {
					inodes = append([]int{int(sock.INode)}, inodes...)
					log.Debug("netlink socket not found, adding entry:  %d:%v -> %v:%d || %d:%v -> %v:%d inode: %d state: %s",
						srcPort, srcIP, dstIP, dstPort,
						sockList[n].ID.SourcePort, sockList[n].ID.Source,
						sockList[n].ID.Destination, sockList[n].ID.DestinationPort,
						sockList[n].INode, TCPStatesMap[sock.State])
				} else {
					log.Debug("netlink socket not found, EXCLUDING entry:  %d:%v -> %v:%d || %d:%v -> %v:%d inode: %d state: %s",
						srcPort, srcIP, dstIP, dstPort,
						sockList[n].ID.SourcePort, sockList[n].ID.Source,
						sockList[n].ID.Destination, sockList[n].ID.DestinationPort,
						sockList[n].INode, TCPStatesMap[sock.State])
				}
			}
		}
	} else {
		log.Debug("netlink socket error: %v - %d:%v -> %v:%d", err, srcPort, srcIP, dstIP, dstPort)
	}

	return uid, inodes
}

// GetSocketInfoByInode dumps the kernel sockets table and searches the given
// inode on it.
func GetSocketInfoByInode(inodeStr string) (*Socket, error) {
	inode, err := strconv.ParseUint(inodeStr, 10, 32)
	if err != nil {
		return nil, err
	}

	type inetStruct struct{ family, proto uint8 }
	socketTypes := []inetStruct{
		{syscall.AF_INET, syscall.IPPROTO_TCP},
		{syscall.AF_INET, syscall.IPPROTO_UDP},
		{syscall.AF_INET6, syscall.IPPROTO_TCP},
		{syscall.AF_INET6, syscall.IPPROTO_UDP},
	}

	for _, socket := range socketTypes {
		socketList, err := SocketsDump(socket.family, socket.proto)
		if err != nil {
			return nil, err
		}
		for idx := range socketList {
			if uint32(inode) == socketList[idx].INode {
				return socketList[idx], nil
			}
		}
	}
	return nil, fmt.Errorf("Inode not found")
}
