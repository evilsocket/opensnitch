package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

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
		// Sometimes we may receive response packets instead of new outbound connections:
		// 443:public-ip -> local-ip:local-port.
		// @see: e090833d29738274c1d171eba53e239c1c49ea7c
		// This occurs mainly when using Conntrack to intercept outbound connections.
		// Swapping connection fields helps to identify the connection + pid + process, and continue working as usual.

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
		deleteEbpfEntry(proto, key)
		if p := isPIDinEventsCache(cacheItem.Pid, cacheItem.UID); p != nil {
			proc = p
			return
		}
	}

	err := ebpfMaps[proto].bpfMap.Lookup(&key, &value)
	if err != nil {
		// key not found
		// sometimes srcIP is 0.0.0.0. Happens especially with UDP sendto()
		// for example:
		//  - 57621:10.0.3.1 -> 10.0.3.255:57621 , reported as: 0.0.0.0 -> 10.0.3.255
		//  - 58306:192.168.11.241 -> 1.2.3.4:54703, reported as: 58306:0.0.0.0 -> 1.2.3.4:54703
		//    ^ incoming connection to port 58306
		// ---
		// Sometimes the srcIP is specified in ancillary messages, using IP_PKTINFO.
		// bind(226, {sa_family=AF_INET6, sin6_port=htons(5353), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::", &sin6_addr), sin6_scope_id=0}, 28) = 0
		// socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0) = 227
		// setsockopt(226, SOL_IPV6, IPV6_MULTICAST_IF, [3], 4) = 0
		// setsockopt(226, SOL_IPV6, IPV6_ADD_MEMBERSHIP, {inet_pton(AF_INET6, "ff02::fb", &ipv6mr_multiaddr), ipv6mr_interface=if_nametoindex("wlp3s0")}, 20) = 0
		//
		nkey := key
		if isIP4 {
			zeroes := make([]byte, 4)
			copy(nkey[8:12], zeroes)
		} else {
			zeroes := make([]byte, 16)
			copy(nkey[20:36], zeroes)
		}
		err = ebpfMaps[proto].bpfMap.Lookup(&nkey, &value)
		if err == nil {
			log.Trace("[eBPF] found via srcIP == 0.0.0.0 (%s): %+v -> %+v", proto, srcIP, dstIP)
			delItemIfFound = false
		}
	}
	if err != nil {
		nkey := key
		if isIP4 {
			copy(nkey[2:6], srcIP)
			copy(nkey[8:12], dstIP)
		} else {
			copy(nkey[2:18], srcIP)
			copy(nkey[20:36], dstIP)
		}
		err = ebpfMaps[proto].bpfMap.Lookup(&nkey, &value)
		if err == nil {
			log.Error("[eBPF] found via dstIP -> srcIP: %+v -> %+v", srcIP, dstIP)
			delItemIfFound = false
		}
	}

	if err != nil {
		// key not found in bpf maps
		return nil
	}

	proc = findConnProcess(&value, k)

	log.Debug("[ebpf conn] adding item to cache: %s", k)
	ebpfCache.addNewItem(k, key, proc.ID, int(value.UID))
	if delItemIfFound {
		deleteEbpfEntry(proto, key)
	}
	return
}

// Check if the PID of the connection is in the cache.
func isPIDinEventsCache(pid, uid int) (proc *procmon.Process) {
	if ev, found := procmon.EventsCache.IsInStoreByPID(pid); found {
		// In some cases, a process may have dropped its privileges, from 0 to 123 for example.
		// In these cases use socket's UID. This is the UID that we've always used,
		ev.Proc.UID = uid
		proc = &ev.Proc
		log.Debug("[ebpf conn] not in cache, but in execEvents, pid: %d, uid: %d -> %s -> %s", proc.ID, proc.UID, proc.Path, proc.Args)
		return proc
	}

	return nil
}

// findConnProcess finds the process' details of a connection.
// By default we only receive the PID of the process, so we need to get
// the rest of the details.
// TODO: get the details from kernel, with mm_struct (exe_file, fd_path, etc).
func findConnProcess(value *networkEventT, connKey string) (proc *procmon.Process) {

	if p := isPIDinEventsCache(int(value.Pid), int(value.UID)); p != nil {
		return p
	}

	// We'll end here if the events module has not been loaded, or if the process is not in cache.
	comm := byteArrayToString(value.Comm[:])
	proc = procmon.NewProcess(int(value.Pid), comm)
	proc.UID = int(value.UID)
	procmon.EventsCache.Add(proc)
	procmon.EventsCache.Update(proc, nil)
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
