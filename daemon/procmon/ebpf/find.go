package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
)

// we need to manually remove old connections from a bpf map

// GetPid looks up process pid in a bpf map. If not found there, then it searches
// already-established TCP connections.
func GetPid(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) (int, int, error) {
	if hostByteOrder == nil {
		return -1, -1, fmt.Errorf("eBPF monitoring method not initialized yet")
	}

	if pid, uid := getPidFromEbpf(proto, srcPort, srcIP, dstIP, dstPort); pid != -1 {
		return pid, uid, nil
	}
	//check if it comes from already established TCP
	if proto == "tcp" || proto == "tcp6" {
		if pid, uid, err := findInAlreadyEstablishedTCP(proto, srcPort, srcIP, dstIP, dstPort); err == nil {
			return pid, uid, nil
		}
	}
	//using netlink.GetSocketInfo to check if UID is 0 (in-kernel connection)
	if uid, _ := daemonNetlink.GetSocketInfo(proto, srcIP, srcPort, dstIP, dstPort); uid == 0 {
		return -100, -100, nil
	}
	if !findAddressInLocalAddresses(srcIP) {
		// systemd-resolved sometimes makes a TCP Fast Open connection to a DNS server (8.8.8.8 on my machine)
		// and we get a packet here with **source** (not detination!!!) IP 8.8.8.8
		// Maybe it's an in-kernel response with spoofed IP because wireshark does not show neither
		// resolved's TCP Fast Open packet, nor the response
		// Until this is better understood, we simply do not allow this machine to make connections with
		// arbitrary source IPs
		return -1, -1, fmt.Errorf("eBPF packet with unknown source IP: %s", srcIP)
	}
	return -1, -1, nil
}

// getPidFromEbpf looks up a connection in bpf map and returns PID if found
// the lookup keys and values are defined in opensnitch.c , e.g.
//
// struct tcp_key_t {
// 	u16 sport;
// 	u32 daddr;
// 	u16 dport;
//  u32 saddr;
// }__attribute__((packed));

// struct tcp_value_t{
// 	u64 pid;
//  u64 uid;
// 	u64 counter;
// }__attribute__((packed));;

func getPidFromEbpf(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) (pid int, uid int) {
	if hostByteOrder == nil {
		return -1, -1
	}
	// Some connections, like broadcasts, are only seen in eBPF once,
	// but some applications send 1 connection per network interface.
	// If we delete the eBPF entry the first time we see it, we won't find
	// the connection the next times.
	delItemIfFound := true

	var key []byte
	var value []byte
	var isIP4 bool = (proto == "tcp") || (proto == "udp") || (proto == "udplite")

	if isIP4 {
		key = make([]byte, 12)
		value = make([]byte, 24)
		copy(key[2:6], dstIP)
		binary.BigEndian.PutUint16(key[6:8], uint16(dstPort))
		copy(key[8:12], srcIP)
	} else { // IPv6
		key = make([]byte, 36)
		value = make([]byte, 24)
		copy(key[2:18], dstIP)
		binary.BigEndian.PutUint16(key[18:20], uint16(dstPort))
		copy(key[20:36], srcIP)
	}
	hostByteOrder.PutUint16(key[0:2], uint16(srcPort))

	k := fmt.Sprint(proto, srcPort, srcIP.String(), dstIP.String(), dstPort)
	cacheItem, isInCache := ebpfCache.isInCache(k)
	if isInCache {
		deleteEbpfEntry(proto, unsafe.Pointer(&key[0]))
		return cacheItem.Pid, cacheItem.UID
	}

	err := m.LookupElement(ebpfMaps[proto].bpfmap, unsafe.Pointer(&key[0]), unsafe.Pointer(&value[0]))
	if err != nil {
		// key not found
		// sometimes srcIP is 0.0.0.0. Happens especially with UDP sendto()
		// for example: 57621:10.0.3.1 -> 10.0.3.255:57621 , reported as: 0.0.0.0 -> 10.0.3.255
		if isIP4 {
			zeroes := make([]byte, 4)
			copy(key[8:12], zeroes)
		} else {
			zeroes := make([]byte, 16)
			copy(key[20:36], zeroes)
		}
		err = m.LookupElement(ebpfMaps[proto].bpfmap, unsafe.Pointer(&key[0]), unsafe.Pointer(&value[0]))
		if err == nil {
			delItemIfFound = false
		}
	}
	if err != nil && proto == "udp" && srcIP.String() == dstIP.String() {
		// very rarely I see this connection. It has srcIP and dstIP == 0.0.0.0 in ebpf map
		// it is a localhost to localhost connection
		// srcIP was already set to 0, set dstIP to zero also
		// TODO try to reproduce it and look for srcIP/dstIP in other kernel structures
		zeroes := make([]byte, 4)
		copy(key[2:6], zeroes)
		err = m.LookupElement(ebpfMaps[proto].bpfmap, unsafe.Pointer(&key[0]), unsafe.Pointer(&value[0]))
	}

	if err != nil {
		// key not found in bpf maps
		return -1, -1
	}
	pid = int(hostByteOrder.Uint32(value[0:4]))
	uid = int(hostByteOrder.Uint32(value[8:12]))

	ebpfCache.addNewItem(k, key, pid, uid)
	if delItemIfFound {
		deleteEbpfEntry(proto, unsafe.Pointer(&key[0]))
	}
	return pid, uid
}

// FindInAlreadyEstablishedTCP searches those TCP connections which were already established at the time
// when opensnitch started
func findInAlreadyEstablishedTCP(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) (int, int, error) {
	alreadyEstablished.RLock()
	defer alreadyEstablished.RUnlock()

	var _alreadyEstablished map[*daemonNetlink.Socket]int
	if proto == "tcp" {
		_alreadyEstablished = alreadyEstablished.TCP
	} else if proto == "tcp6" {
		_alreadyEstablished = alreadyEstablished.TCPv6
	}

	for sock, v := range _alreadyEstablished {
		if (*sock).ID.SourcePort == uint16(srcPort) && (*sock).ID.Source.Equal(srcIP) &&
			(*sock).ID.Destination.Equal(dstIP) && (*sock).ID.DestinationPort == uint16(dstPort) {
			return v, int((*sock).UID), nil
		}
	}
	return -1, -1, fmt.Errorf("eBPF inode not found")
}

//returns true if addr is in the list of this machine's addresses
func findAddressInLocalAddresses(addr net.IP) bool {
	lock.Lock()
	defer lock.Unlock()
	for _, a := range localAddresses {
		if addr.String() == a.String() {
			return true
		}
	}
	return false
}
