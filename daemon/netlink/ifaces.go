package netlink

import (
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/vishvananda/netlink"
)

// GetLocalAddrs returns the list of local IPs
func GetLocalAddrs() map[string]netlink.Addr {
	localAddresses := make(map[string]netlink.Addr)
	addr, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		log.Error("eBPF error looking up this machine's addresses via netlink: %v", err)
		return nil
	}
	for _, a := range addr {
		log.Debug("local addr: %+v\n", a)
		localAddresses[a.IP.String()] = a
	}

	return localAddresses
}

// AddrUpdateToAddr translate AddrUpdate struct to Addr
func AddrUpdateToAddr(addr *netlink.AddrUpdate) netlink.Addr {
	return netlink.Addr{
		IPNet:       &addr.LinkAddress,
		LinkIndex:   addr.LinkIndex,
		Flags:       addr.Flags,
		Scope:       addr.Scope,
		PreferedLft: addr.PreferedLft,
		ValidLft:    addr.ValidLft,
	}
}
