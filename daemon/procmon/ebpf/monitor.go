package ebpf

import (
	"syscall"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/vishvananda/netlink"
)

// we need to manually remove old connections from a bpf map
// since when a bpf map is full it doesn't allow any more insertions
func monitorMaps() {
	for {
		if isStopped() {
			return
		}
		time.Sleep(time.Second * 5)
		for name := range ebpfMaps {
			// using a pointer to the map doesn't delete the items.
			// bpftool still counts them.
			if items := getItems(name, name == "tcp6" || name == "udp6"); items > 500 {
				deleted := deleteOldItems(name, name == "tcp6" || name == "udp6", items/2)
				log.Debug("[ebpf] old items deleted: %d", deleted)
			}
		}
	}
}

func monitorCache() {
	for {
		select {
		case <-ebpfCacheTicker.C:
			if isStopped() {
				return
			}
			ebpfCache.DeleteOldItems()
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
				if socketsAreEqual(aesock, sock) {
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
					if socketsAreEqual(aesock, sock) {
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

func socketsAreEqual(aSocket, bSocket *daemonNetlink.Socket) bool {
	return ((*aSocket).INode == (*bSocket).INode &&
		//inodes are unique enough, so the matches below will never have to be checked
		(*aSocket).ID.SourcePort == (*bSocket).ID.SourcePort &&
		(*aSocket).ID.Source.Equal((*bSocket).ID.Source) &&
		(*aSocket).ID.Destination.Equal((*bSocket).ID.Destination) &&
		(*aSocket).ID.DestinationPort == (*bSocket).ID.DestinationPort &&
		(*aSocket).UID == (*bSocket).UID)
}
