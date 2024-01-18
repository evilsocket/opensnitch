package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/evilsocket/opensnitch/daemon/procmon"
)

// we need to manually remove old connections from a bpf map

// GetPid looks up process pid in a bpf map.
// If it's not found, it searches already-established TCP connections.
// Returns the process if found.
// Additionally, if the process has been found by swapping fields, it'll return
// a flag indicating it.
func GetPid(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) (*procmon.Process, bool, error) {
	if proc := getPidFromEbpf(proto, srcPort, srcIP, dstIP, dstPort); proc != nil {
		return proc, false, nil
	}
	if findAddressInLocalAddresses(dstIP) {
		// NOTE:
		// Sometimes every outbound connection has the fields swapped:
		// 443:public-ip -> local-ip:local-port , like if it was a response (but it's not).
		// Swapping connection fields helps to identify the connection + pid + process, and continue working as usual
		// when systemd-resolved is being used.
		// This seems to be the case when using conntrack to intercept outbound connections, specially for TCP.
		// @see: e090833d29738274c1d171eba53e239c1c49ea7c

		if proc := getPidFromEbpf(proto, dstPort, dstIP, srcIP, srcPort); proc != nil {
			return proc, true, fmt.Errorf("[ebpf conn] FIXME: found swapping fields, systemd-resolved is that you? set DNS=x.x.x.x to your DNS server in /etc/systemd/resolved.conf to workaround this problem")
		}
		return nil, false, fmt.Errorf("[ebpf conn] unknown source IP: %s", srcIP)
	}
	//check if it comes from already established TCP
	if proto == "tcp" || proto == "tcp6" {
		if pid, uid, err := findInAlreadyEstablishedTCP(proto, srcPort, srcIP, dstIP, dstPort); err == nil {
			proc := procmon.NewProcess(pid, "")
			proc.UID = uid
			return proc, false, nil
		}
	}

	//using netlink.GetSocketInfo to check if UID is 0 (in-kernel connection)
	if uid, _ := daemonNetlink.GetSocketInfo(proto, srcIP, srcPort, dstIP, dstPort); uid == 0 {
		return nil, false, nil
	}
	return nil, false, nil
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
//  char[TASK_COMM_LEN] comm; // 16 bytes
// }__attribute__((packed));

func getPidFromEbpf(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) (proc *procmon.Process) {
	// Some connections, like broadcasts, are only seen in eBPF once,
	// but some applications send 1 connection per network interface.
	// If we delete the eBPF entry the first time we see it, we won't find
	// the connection the next times.
	delItemIfFound := true

	_, ok := ebpfMaps[proto]
	if !ok {
		return
	}

	var value networkEventT
	var key []byte
	var isIP4 bool = (proto == "tcp") || (proto == "udp") || (proto == "udplite")

	if isIP4 {
		key = make([]byte, 12)
		copy(key[2:6], dstIP)
		binary.BigEndian.PutUint16(key[6:8], uint16(dstPort))
		copy(key[8:12], srcIP)
	} else { // IPv6
		key = make([]byte, 36)
		copy(key[2:18], dstIP)
		binary.BigEndian.PutUint16(key[18:20], uint16(dstPort))
		copy(key[20:36], srcIP)
	}
	hostByteOrder.PutUint16(key[0:2], uint16(srcPort))

	k := core.ConcatStrings(
		proto,
		strconv.FormatUint(uint64(srcPort), 10),
		srcIP.String(),
		dstIP.String(),
		strconv.FormatUint(uint64(dstPort), 10))
	if cacheItem, isInCache := ebpfCache.isInCache(k); isInCache {
		deleteEbpfEntry(proto, unsafe.Pointer(&key[0]))
		if ev, found := procmon.EventsCache.IsInStoreByPID(cacheItem.Pid); found {
			proc = &ev.Proc
			log.Debug("[ebpf conn] in cache: %s, %d -> %s", k, proc.ID, proc.Path)
			return
		}
		log.Info("[ebpf conn] in cache, with no proc %s, %d", k, cacheItem.Pid)
		return
	}

	err := m.LookupElement(ebpfMaps[proto].bpfmap, unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
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
		err = m.LookupElement(ebpfMaps[proto].bpfmap, unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
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
		err = m.LookupElement(ebpfMaps[proto].bpfmap, unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
	}

	if err != nil {
		// key not found in bpf maps
		return nil
	}

	proc = findConnProcess(&value, k)

	log.Debug("[ebpf conn] adding item to cache: %s", k)
	ebpfCache.addNewItem(k, key, proc.ID)
	if delItemIfFound {
		deleteEbpfEntry(proto, unsafe.Pointer(&key[0]))
	}
	return
}

// findConnProcess finds the process' details of a connection.
// By default we only receive the PID of the process, so we need to get
// the rest of the details.
// TODO: get the details from kernel, with mm_struct (exe_file, fd_path, etc).
func findConnProcess(value *networkEventT, connKey string) (proc *procmon.Process) {

	// Use socket's UID. A process may have dropped privileges.
	// This is the UID that we've always used.

	if ev, found := procmon.EventsCache.IsInStoreByPID(int(value.Pid)); found {
		ev.Proc.UID = int(value.UID)
		proc = &ev.Proc
		log.Debug("[ebpf conn] not in cache, but in execEvents: %s, %d -> %s -> %s", connKey, proc.ID, proc.Path, proc.Args)
		return
	}

	// We'll end here if the events module has not been loaded, or if the process is not in cache.
	comm := byteArrayToString(value.Comm[:])
	proc = procmon.NewProcess(int(value.Pid), comm)
	proc.UID = int(value.UID)
	procmon.EventsCache.Add(proc)
	log.Debug("[ebpf conn] not in cache, NOR in execEvents: %s, %d -> %s -> %s", connKey, proc.ID, proc.Path, proc.Args)

	return
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
	lock.RLock()
	_, found := localAddresses[addr.String()]
	lock.RUnlock()
	return found
}
