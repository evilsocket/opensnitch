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
		select {
		case <-ctxTasks.Done():
			goto Exit
		default:
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
Exit:
}

func monitorCache() {
	for {
		select {
		case <-ctxTasks.Done():
			goto Exit
		case <-ebpfCacheTicker.C:
			ebpfCache.DeleteOldItems()
		}
	}
Exit:
}

// maintain a list of this machine's local addresses
func monitorLocalAddresses() {
	newAddrChan := make(chan netlink.AddrUpdate)
	done := make(chan struct{})
	defer close(done)

	lock.Lock()
	localAddresses = daemonNetlink.GetLocalAddrs()
	lock.Unlock()

	netlink.AddrSubscribeWithOptions(newAddrChan, done,
		netlink.AddrSubscribeOptions{
			ErrorCallback: func(err error) {
				log.Error("AddrSubscribeWithOptions error: %s", err)
			},
			ListExisting: true,
		})

	for {
		select {
		case <-ctxTasks.Done():
			done <- struct{}{}
			goto Exit
		case addr := <-newAddrChan:
			if addr.NewAddr && !findAddressInLocalAddresses(addr.LinkAddress.IP) {
				log.Debug("local addr added: %+v\n", addr)
				lock.Lock()

				localAddresses[addr.LinkAddress.IP.String()] = daemonNetlink.AddrUpdateToAddr(&addr)

				lock.Unlock()
			} else if !addr.NewAddr {
				log.Debug("local addr removed: %+v\n", addr)
				lock.Lock()
				delete(localAddresses, addr.LinkAddress.IP.String())
				lock.Unlock()
			}
		}
	}
Exit:
	log.Debug("monitorLocalAddresses exited")
}

// monitorAlreadyEstablished makes sure that when an already-established connection is closed
// it will be removed from alreadyEstablished. If we don't do this and keep the alreadyEstablished entry forever,
// then after the genuine process quits,a malicious process may reuse PID-srcPort-srcIP-dstPort-dstIP
func monitorAlreadyEstablished() {
	tcperr := 0
	errLimitExceeded := func() bool {
		if tcperr > 100 {
			log.Debug("monitorAlreadyEstablished() generated too much errors")
			return true
		}
		tcperr++

		return false
	}

	for {
		select {
		case <-ctxTasks.Done():
			goto Exit
		default:
			time.Sleep(time.Second * 2)
			socketListTCP, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET), uint8(syscall.IPPROTO_TCP))
			if err != nil {
				log.Debug("monitorAlreadyEstablished(), error dumping TCP sockets via netlink (%d): %s", tcperr, err)
				if errLimitExceeded() {
					goto Exit
				}

				continue
			}
			alreadyEstablished.Lock()
			for aesock := range alreadyEstablished.TCP {
				found := false
				for _, sock := range socketListTCP {
					if daemonNetlink.SocketsAreEqual(aesock, sock) {
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
					if errLimitExceeded() {
						goto Exit
					}
					log.Debug("monitorAlreadyEstablished(), error dumping TCPv6 sockets via netlink (%d): %s", tcperr, err)

					continue
				}
				alreadyEstablished.Lock()
				for aesock := range alreadyEstablished.TCPv6 {
					found := false
					for _, sock := range socketListTCPv6 {
						if daemonNetlink.SocketsAreEqual(aesock, sock) {
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
Exit:
	log.Debug("monitorAlreadyEstablished exited")
}
