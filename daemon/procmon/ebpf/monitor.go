package ebpf

import (
	"syscall"
	"time"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	elf "github.com/iovisor/gobpf/elf"
	"github.com/vishvananda/netlink"
)

// we need to manually remove old connections from a bpf map
// since when a bpf map is full it doesn't allow any more insertions
func monitorMaps() {
	zeroKey := make([]byte, 4)
	for {
		time.Sleep(time.Second * 1)
		if isStopped() {
			return
		}
		for name, ebpfMap := range ebpfMaps {
			value := make([]byte, 8)
			if err := m.LookupElement(ebpfMap.counterMap,
				unsafe.Pointer(&zeroKey[0]), unsafe.Pointer(&value[0])); err != nil {
				log.Error("eBPF m.LookupElement error: %v", err)
			}
			lock.RLock()
			counterValue := hostByteOrder.Uint64(value)
			lock.RUnlock()
			if counterValue-ebpfMap.lastPurgedMax > 10000 {
				ebpfMap.lastPurgedMax = counterValue - 5000
				deleteOld(ebpfMap.bpfmap, name == "tcp6" || name == "udp6", ebpfMap.lastPurgedMax)
			}
		}
	}
}

// maintains a list of this machine's local addresses
// TODO: use netlink.AddrSubscribeWithOptions()
func monitorLocalAddresses() {
	for {
		addr, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
		if err != nil {
			log.Error("eBPF error looking up this machine's addresses via netlink: %v", err)
			continue
		}
		lock.Lock()
		localAddresses = nil
		for _, a := range addr {
			localAddresses = append(localAddresses, a.IP)
		}
		lock.Unlock()
		time.Sleep(time.Second * 1)
		if isStopped() {
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
		if isStopped() {
			return
		}
		socketListTCP, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET), uint8(syscall.IPPROTO_TCP))
		if err != nil {
			log.Debug("eBPF error in dumping TCP sockets via netlink")
			continue
		}
		alreadyEstablished.Lock()
		for aesock := range alreadyEstablished.TCP {
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
				delete(alreadyEstablished.TCP, aesock)
			}
		}
		alreadyEstablished.Unlock()

		if core.IPv6Enabled {
			socketListTCPv6, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET6), uint8(syscall.IPPROTO_TCP))
			if err != nil {
				log.Debug("eBPF error in dumping TCPv6 sockets via netlink: %s", err)
				continue
			}
			alreadyEstablished.Lock()
			for aesock := range alreadyEstablished.TCPv6 {
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
					delete(alreadyEstablished.TCPv6, aesock)
				}
			}
			alreadyEstablished.Unlock()
		}
	}
}

// delete all map's elements which have counter value <= maxToDelete
func deleteOld(bpfmap *elf.Map, isIPv6 bool, maxToDelete uint64) {
	var lookupKey []byte
	var nextKey []byte
	var value []byte
	if !isIPv6 {
		lookupKey = make([]byte, 12)
		nextKey = make([]byte, 12)
		value = make([]byte, 24)
	} else {
		lookupKey = make([]byte, 36)
		nextKey = make([]byte, 36)
		value = make([]byte, 24)
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
			log.Error("eBPF LookupNextElement error: %v", err)
			return
		}
		if firstrun {
			// on first run lookupKey is a dummy, nothing to delete
			firstrun = false
			copy(lookupKey, nextKey)
			continue
		}
		// last 8 bytes of value is counter value
		lock.RLock()
		counterValue := hostByteOrder.Uint64(value[16:24])
		lock.RUnlock()
		if counterValue > maxToDelete {
			copy(lookupKey, nextKey)
			continue
		}
		if err := m.DeleteElement(bpfmap, unsafe.Pointer(&lookupKey[0])); err != nil {
			log.Error("eBPF DeleteElement error: %v", err)
			return
		}
		if !ok { //reached end of map
			break
		}
		copy(lookupKey, nextKey)
	}
}
