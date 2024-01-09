package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

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
		// FIXME: systemd-resolved sometimes makes a TCP Fast Open connection to a DNS server (8.8.8.8 on my machine)
		// and we get a packet here with **source** (not detination!!!) IP 8.8.8.8
		// Maybe it's an in-kernel response with spoofed IP because resolved's TCP Fast Open packet, nor the response.
		// Another scenario when systemd-resolved or dnscrypt-proxy is used, is that every outbound connection has
		// the fields swapped:
		// 443:public-ip -> local-ip:local-port , like if it was a response (but it's not).
		// Swapping connection fields helps to identify the connection + pid + process, and continue working as usual
		// when systemd-resolved is being used. But we should understand why is this happenning.

		if proc := getPidFromEbpf(proto, dstPort, dstIP, srcIP, srcPort); proc != nil {
			return proc, true, fmt.Errorf("[ebpf conn] FIXME: found swapping fields, systemd-resolved is that you? set DNS=x.x.x.x to your DNS server in /etc/systemd/resolved.conf to workaround this problem")
		}
		return nil, false, fmt.Errorf("[ebpf conn] unknown source IP: %s", srcIP)
	}
	//check if it comes from already established TCP
	if proto == "tcp" || proto == "tcp6" {
		if pid, uid, err := findInAlreadyEstablishedTCP(proto, srcPort, srcIP, dstIP, dstPort); err == nil {
			proc := procmon.NewProcess(pid, "")
			proc.GetInfo()
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

	k := fmt.Sprint(proto, srcPort, srcIP.String(), dstIP.String(), dstPort)
	if cacheItem, isInCache := ebpfCache.isInCache(k); isInCache {
		// should we re-read the info?
		// environ vars might have changed
		//proc.GetInfo()
		deleteEbpfEntry(proto, unsafe.Pointer(&key[0]))
		proc = &cacheItem.Proc
		log.Debug("[ebpf conn] in cache: %s, %d -> %s", k, proc.ID, proc.Path)
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
	ebpfCache.addNewItem(k, key, *proc)
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
	comm := byteArrayToString(value.Comm[:])
	proc = procmon.NewProcess(int(value.Pid), comm)
	// Use socket's UID. A process may have dropped privileges.
	// This is the UID that we've always used.
	proc.UID = int(value.UID)

	err := proc.ReadPath()
	if ev, found := execEvents.isInStore(uint32(value.Pid)); found {
		// use socket's UID. See above why ^
		ev.Proc.UID = proc.UID
		ev.Proc.ReadCmdline()
		// if proc's ReadPath() has been successfull, and the path received via the execve tracepoint differs,
		// use proc's path.
		// Sometimes we received from the tracepoint a wrong/non-existent path.
		// Othertimes we receive a "helper" that executes the real binary which opens the connection.
		// Downsides: for execveat() executions we won't display the original binary.
		if err == nil && ev.Proc.Path != proc.Path {
			proc.ReadCmdline()
			ev.Proc.Path = proc.Path
			ev.Proc.Args = proc.Args
		}
		proc = &ev.Proc

		log.Debug("[ebpf conn] not in cache, but in execEvents: %s, %d -> %s", connKey, proc.ID, proc.Path)
	} else {
		log.Debug("[ebpf conn] not in cache, NOR in execEvents: %s, %d -> %s", connKey, proc.ID, proc.Path)
		// We'll end here if the events module has not been loaded, or if the process is not in cache.
		proc.GetInfo()
		execEvents.add(uint32(value.Pid),
			*NewExecEvent(uint32(value.Pid), 0, uint32(value.UID), proc.Path, value.Comm),
			*proc)
	}

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
	lock.Lock()
	defer lock.Unlock()
	_, found := localAddresses[addr.String()]
	return found
}
