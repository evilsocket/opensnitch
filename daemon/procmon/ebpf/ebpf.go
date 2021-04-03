package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/vishvananda/netlink"

	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	elf "github.com/iovisor/gobpf/elf"
)

//contains pointers to ebpf maps for a given protocol (tcp/udp/v6)
type ebpfMapsForProto struct {
	counterMap    *elf.Map
	bpfmap        *elf.Map
	lastPurgedMax uint64 // max counter value up to and including which the map was purged on the last purge
}

var (
	m        *elf.Module
	mapSize  = 12000
	ebpfMaps map[string]*ebpfMapsForProto
	//connections which were established at the time when opensnitch started
	alreadyEstablishedTCP   = make(map[*daemonNetlink.Socket]int)
	alreadyEstablishedTCPv6 = make(map[*daemonNetlink.Socket]int)
	//stop == true is a signal for all goroutines to stop
	stop = false
	// list of local addresses of this machine
	localAddresses     []net.IP
	localAddressesLock sync.RWMutex
	hostByteOrder      binary.ByteOrder
)

//Start installs ebpf kprobes
func Start() error {
	m = elf.NewModule("/etc/opensnitchd/opensnitch.o")
	if err := m.Load(nil); err != nil {
		log.Error("Failed to load /etc/opensnitchd/opensnitch.o", err)
		return err
	}

	// if previous shutdown was unclean, then we must remove the dangling kprobe
	// and install it again (close the module and load it again)
	if err := m.EnableKprobes(0); err != nil {
		m.Close()
		if err := m.Load(nil); err != nil {
			log.Error("Failed to load /etc/opensnitchd/opensnitch.o", err)
			return err
		}
		if err := m.EnableKprobes(0); err != nil {
			log.Error("Error when enabling kprobes", err)
			return err
		}
	}

	// init all connection counters to 0
	zeroKey := make([]byte, 4)
	zeroValue := make([]byte, 8)
	for _, name := range []string{"tcpcounter", "tcpv6counter", "udpcounter", "udpv6counter"} {
		err := m.UpdateElement(m.Map(name), unsafe.Pointer(&zeroKey[0]), unsafe.Pointer(&zeroValue[0]), 0)
		if err != nil {
			log.Error("Could not init counters to zero", err)
			return err
		}
	}

	//determine host byte order
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		hostByteOrder = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		hostByteOrder = binary.BigEndian
	default:
		log.Error("Could not determine host byte order.")
	}

	ebpfMaps = map[string]*ebpfMapsForProto{
		"tcp": {lastPurgedMax: 0,
			counterMap: m.Map("tcpcounter"),
			bpfmap:     m.Map("tcpMap")},
		"tcp6": {lastPurgedMax: 0,
			counterMap: m.Map("tcpv6counter"),
			bpfmap:     m.Map("tcpv6Map")},
		"udp": {lastPurgedMax: 0,
			counterMap: m.Map("udpcounter"),
			bpfmap:     m.Map("udpMap")},
		"udp6": {lastPurgedMax: 0,
			counterMap: m.Map("udpv6counter"),
			bpfmap:     m.Map("udpv6Map")},
	}

	// save already established connections
	socketListTCP, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET), uint8(syscall.IPPROTO_TCP))
	if err != nil {
		log.Error("Could not dump TCP sockets via netlink", err)
		return err
	}
	for _, sock := range socketListTCP {
		inode := int((*sock).INode)
		pid := procmon.GetPIDFromINode(inode, fmt.Sprint(inode,
			(*sock).ID.Source, (*sock).ID.SourcePort, (*sock).ID.Destination, (*sock).ID.DestinationPort))
		alreadyEstablishedTCP[sock] = pid
	}

	socketListTCPv6, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET6), uint8(syscall.IPPROTO_TCP))
	if err != nil {
		log.Error("Could not dump TCPv6 sockets via netlink", err)
		return err
	}
	for _, sock := range socketListTCPv6 {
		inode := int((*sock).INode)
		pid := procmon.GetPIDFromINode(inode, fmt.Sprint(inode,
			(*sock).ID.Source, (*sock).ID.SourcePort, (*sock).ID.Destination, (*sock).ID.DestinationPort))
		alreadyEstablishedTCPv6[sock] = pid
	}

	go monitorMaps()
	go monitorLocalAddresses()
	go monitorAlreadyEstablished()
	return nil
}

func Stop() {
	stop = true
	m.Close()
}

// delete all map's elements which have counter value <= maxToDelete
func deleteOld(bpfmap *elf.Map, isIPv6 bool, maxToDelete uint64) {
	var lookupKey []byte
	var nextKey []byte
	var value []byte
	if !isIPv6 {
		lookupKey = make([]byte, 12)
		nextKey = make([]byte, 12)
		value = make([]byte, 16)
	} else {
		lookupKey = make([]byte, 36)
		nextKey = make([]byte, 36)
		value = make([]byte, 16)
	}
	firstrun := true
	i := 0
	for {
		i++
		if i > 12000 {
			// there were more iterations than the max amount of elements in map
			// TODO find out what causes the endless loop
			// maybe because ebpf prog modified the map while we were iterating
			log.Error("Breaking because endless loop was detected in deleteOld")
			break
		}
		ok, err := m.LookupNextElement(bpfmap, unsafe.Pointer(&lookupKey[0]),
			unsafe.Pointer(&nextKey[0]), unsafe.Pointer(&value[0]))
		if err != nil {
			log.Error("LookupNextElement error", err)
			return
		}
		if firstrun {
			// on first run lookupKey is a dummy, nothing to delete
			firstrun = false
			copy(lookupKey, nextKey)
			continue
		}
		// last 8 bytes of value is counter value
		counterValue := hostByteOrder.Uint64(value[8:16])
		if counterValue > maxToDelete {
			copy(lookupKey, nextKey)
			continue
		}
		if err := m.DeleteElement(bpfmap, unsafe.Pointer(&lookupKey[0])); err != nil {
			log.Error("DeleteElement error", err)
			return
		}
		if !ok { //reached end of map
			break
		}
		copy(lookupKey, nextKey)
	}
}

// we need to manually remove old connections from a bpf map
// since when a bpf map is full it doesn't allow any more insertions
func monitorMaps() {
	zeroKey := make([]byte, 4)
	for {
		time.Sleep(time.Second * 1)
		if stop {
			return
		}
		for name, ebpfMap := range ebpfMaps {
			value := make([]byte, 8)
			if err := m.LookupElement(ebpfMap.counterMap,
				unsafe.Pointer(&zeroKey[0]), unsafe.Pointer(&value[0])); err != nil {
				log.Error("m.LookupElement", err)
			}
			counterValue := hostByteOrder.Uint64(value)
			//fmt.Println("counterValue, ebpfMap.lastPurgedMax", counterValue, ebpfMap.lastPurgedMax)
			if counterValue-ebpfMap.lastPurgedMax > 10000 {
				ebpfMap.lastPurgedMax = counterValue - 5000
				deleteOld(ebpfMap.bpfmap, name == "tcp6" || name == "udp6", ebpfMap.lastPurgedMax)
			}
		}
	}
}

// GetPid looks up process pid in a bpf map. If not found there, then it searches
// already-eastablished TCP connections
func GetPid(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) (int, error) {
	if pid := getPidFromEbpf(proto, srcPort, srcIP, dstIP, dstPort); pid != -1 {
		return pid, nil
	}
	//check if it comes from already established TCP
	if proto == "tcp" || proto == "tcp6" {
		if pid, err := findInAlreadyEstablishedTCP(proto, srcPort, srcIP, dstIP, dstPort); err == nil && pid != -1 {
			return pid, nil
		}
	}
	//using netlink.GetSocketInfo to check if UID is 0 (in-kernel connection)
	if uid, _ := daemonNetlink.GetSocketInfo(proto, srcIP, srcPort, dstIP, dstPort); uid == 0 {
		return -100, nil
	}
	if !findAddressInLocalAddresses(srcIP) {
		// systemd-resolved sometimes makes a TCP Fast Open connection to a DNS server (8.8.8.8 on my machine)
		// and we get a packet here with **source** (not detination!!!) IP 8.8.8.8
		// Maybe it's an in-kernel response with spoofed IP because wireshark does not show neither
		// resolved's TCP Fast Open packet, nor the response
		// Until this is better understood, we simply do not allow this machine to make connections with
		// arbitrary source IPs
		return -1, fmt.Errorf("Packet with unknown source IP: %s", srcIP)
	}
	return -1, nil
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
// 	u64 counter;
// }__attribute__((packed));;

func getPidFromEbpf(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) int {
	var key []byte
	var value []byte
	var isIP4 bool = (proto == "tcp") || (proto == "udp") || (proto == "udplite")

	if isIP4 {
		key = make([]byte, 12)
		value = make([]byte, 16)
		copy(key[2:6], dstIP)
		binary.BigEndian.PutUint16(key[6:8], uint16(dstPort))
		copy(key[8:12], srcIP)
	} else { // IPv6
		key = make([]byte, 36)
		value = make([]byte, 16)
		copy(key[2:18], dstIP)
		binary.BigEndian.PutUint16(key[18:20], uint16(dstPort))
		copy(key[20:36], srcIP)
	}
	hostByteOrder.PutUint16(key[0:2], uint16(srcPort))

	err := m.LookupElement(ebpfMaps[proto].bpfmap, unsafe.Pointer(&key[0]), unsafe.Pointer(&value[0]))
	if err != nil {
		// key not found
		// maybe srcIP is 0.0.0.0 Happens especially with UDP sendto()
		// TODO: can this happen with TCP?
		if isIP4 {
			zeroes := make([]byte, 4)
			copy(key[8:12], zeroes)
		} else {
			zeroes := make([]byte, 16)
			copy(key[20:36], zeroes)
		}
		err = m.LookupElement(ebpfMaps[proto].bpfmap, unsafe.Pointer(&key[0]), unsafe.Pointer(&value[0]))
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
		// key not found in bpf map
		return -1
	}
	pid := int(hostByteOrder.Uint32(value[0:4]))
	return pid
}

// FindInAlreadyEstablishedTCP searches those TCP connections which were already established at the time
// when opensnitch started
func findInAlreadyEstablishedTCP(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) (int, error) {
	var alreadyEstablished map[*daemonNetlink.Socket]int
	if proto == "tcp" {
		alreadyEstablished = alreadyEstablishedTCP
	} else if proto == "tcp6" {
		alreadyEstablished = alreadyEstablishedTCPv6
	}
	for sock, v := range alreadyEstablished {
		if (*sock).ID.SourcePort == uint16(srcPort) && (*sock).ID.Source.Equal(srcIP) &&
			(*sock).ID.Destination.Equal(dstIP) && (*sock).ID.DestinationPort == uint16(dstPort) {
			return v, nil
		}
	}
	return 0, fmt.Errorf("Inode not found")
}

//returns true if addr is in the list of this machine's addresses
func findAddressInLocalAddresses(addr net.IP) bool {
	localAddressesLock.Lock()
	defer localAddressesLock.Unlock()
	for _, a := range localAddresses {
		if addr.String() == a.String() {
			return true
		}
	}
	return false
}

// maintains a list of this machine's local addresses
func monitorLocalAddresses() {
	for {
		addr, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
		if err != nil {
			log.Error("Error looking up this machine's addresses via netlink", err)
			continue
		}
		localAddressesLock.Lock()
		localAddresses = nil
		for _, a := range addr {
			localAddresses = append(localAddresses, a.IP)
		}
		localAddressesLock.Unlock()
		time.Sleep(time.Second * 1)
		if stop {
			return
		}
	}
}

// monitorAlreadyEstablished makes sure that when an already-established connection is closed
// it will be removed from alreadyEstablished. If we don't do this and keep the alreadyEstablished entry forever,
// then after the genuine process quits,a malicious process may reuse PID-srcPort-srcIP-dstPort-dstIP
func monitorAlreadyEstablished() {
	for {
		time.Sleep(time.Second * 1)
		if stop {
			return
		}
		socketListTCP, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET), uint8(syscall.IPPROTO_TCP))
		if err != nil {
			log.Error("Error in dumping TCP sockets via netlink")
			continue
		}
		for aesock := range alreadyEstablishedTCP {
			found := false
			for _, sock := range socketListTCP {
				if (*aesock).INode == (*sock).INode &&
					//inodes are unique enough, so the matches below will never have to be checked
					(*aesock).ID.SourcePort == (*sock).ID.SourcePort &&
					(*aesock).ID.Source.Equal((*sock).ID.Source) &&
					(*aesock).ID.Destination.Equal((*sock).ID.Destination) &&
					(*aesock).ID.DestinationPort == (*sock).ID.DestinationPort &&
					(*aesock).UID == (*sock).UID {
					found = true
					break
				}
			}
			if !found {
				delete(alreadyEstablishedTCP, aesock)
			}
		}

		socketListTCPv6, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET6), uint8(syscall.IPPROTO_TCP))
		if err != nil {
			log.Error("Error in dumping TCPv6 sockets via netlink")
			continue
		}
		for aesock := range alreadyEstablishedTCPv6 {
			found := false
			for _, sock := range socketListTCPv6 {
				if (*aesock).INode == (*sock).INode &&
					//inodes are unique enough, so the matches below will never have to be checked
					(*aesock).ID.SourcePort == (*sock).ID.SourcePort &&
					(*aesock).ID.Source.Equal((*sock).ID.Source) &&
					(*aesock).ID.Destination.Equal((*sock).ID.Destination) &&
					(*aesock).ID.DestinationPort == (*sock).ID.DestinationPort &&
					(*aesock).UID == (*sock).UID {
					found = true
					break
				}
			}
			if !found {
				delete(alreadyEstablishedTCPv6, aesock)
			}
		}
	}
}

//Not in use, ~4usec faster lookup compared to m.LookupElement()

//mimics union bpf_attr's anonymous struct used by BPF_MAP_*_ELEM commands
//from <linux_headers>/include/uapi/linux/bpf.h
type bpf_lookup_elem_t struct {
	map_fd uint64 //even though in bpf.h its type is __u32, we must make it 8 bytes long
	//because "key" is of type __aligned_u64, i.e. "key" must be aligned on an 8-byte boundary
	key   uintptr
	value uintptr
}

//make bpf() syscall with bpf_lookup prepared by the caller
func makeBpfSyscall(bpf_lookup *bpf_lookup_elem_t) uintptr {
	BPF_MAP_LOOKUP_ELEM := 1 //cmd number
	syscall_BPF := 321       //syscall number
	sizeOfStruct := 24       //sizeof bpf_lookup_elem_t struct

	r1, _, _ := syscall.Syscall(uintptr(syscall_BPF), uintptr(BPF_MAP_LOOKUP_ELEM),
		uintptr(unsafe.Pointer(bpf_lookup)), uintptr(sizeOfStruct))
	return r1
}

// print map contents. used only for debugging
func dumpMap(bpfmap *elf.Map, isIPv6 bool) {
	var lookupKey []byte
	var nextKey []byte
	var value []byte
	if !isIPv6 {
		lookupKey = make([]byte, 12)
		nextKey = make([]byte, 12)
		value = make([]byte, 16)
	} else {
		lookupKey = make([]byte, 36)
		nextKey = make([]byte, 36)
		value = make([]byte, 16)
	}
	firstrun := true
	i := 0
	for {
		i++
		ok, err := m.LookupNextElement(bpfmap, unsafe.Pointer(&lookupKey[0]),
			unsafe.Pointer(&nextKey[0]), unsafe.Pointer(&value[0]))
		if err != nil {
			log.Error("LookupNextElement error", err)
			return
		}
		if firstrun {
			// on first run lookupKey is a dummy, nothing to delete
			firstrun = false
			copy(lookupKey, nextKey)
			continue
		}
		fmt.Println("key, value", lookupKey, value)

		if !ok { //reached end of map
			break
		}
		copy(lookupKey, nextKey)
	}
}

//PrintEverything prints all the stats. used only for debugging
func PrintEverything() {
	bash, _ := exec.LookPath("bash")
	//get the number of the first map
	out, err := exec.Command(bash, "-c", "bpftool map show | head -n 1 | cut -d ':' -f1").Output()
	if err != nil {
		fmt.Println("bpftool map dump name tcpMap ", err)
	}
	i, _ := strconv.Atoi(string(out[:len(out)-1]))
	fmt.Println("i is", i)

	//dump all maps for analysis
	for j := i; j < i+14; j++ {
		_, _ = exec.Command(bash, "-c", "bpftool map dump id "+strconv.Itoa(j)+" > dump"+strconv.Itoa(j)).Output()
	}

	for sock1, v := range alreadyEstablishedTCP {
		fmt.Println(*sock1, v)
	}
	fmt.Println("---------------------")
	for sock1, v := range alreadyEstablishedTCPv6 {
		fmt.Println(*sock1, v)
	}
	fmt.Println("---------------------")
	sockets, _ := daemonNetlink.SocketsDump(syscall.AF_INET, syscall.IPPROTO_TCP)
	for idx := range sockets {
		fmt.Println("socket tcp: ", sockets[idx])
	}
	fmt.Println("---------------------")
	sockets, _ = daemonNetlink.SocketsDump(syscall.AF_INET6, syscall.IPPROTO_TCP)
	for idx := range sockets {
		fmt.Println("socket tcp6: ", sockets[idx])
	}
	fmt.Println("---------------------")
	sockets, _ = daemonNetlink.SocketsDump(syscall.AF_INET, syscall.IPPROTO_UDP)
	for idx := range sockets {
		fmt.Println("socket udp: ", sockets[idx])
	}
	fmt.Println("---------------------")
	sockets, _ = daemonNetlink.SocketsDump(syscall.AF_INET6, syscall.IPPROTO_UDP)
	for idx := range sockets {
		fmt.Println("socket udp6: ", sockets[idx])
	}

}
