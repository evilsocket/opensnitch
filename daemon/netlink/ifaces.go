package netlink

import (
	"net"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/vishvananda/netlink"
)

// https://cs.opensource.google/go/go/+/refs/tags/go1.20.6:src/net/ip.go;l=133
// TODO: remove when upgrading go version.
func isPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return len(ip) == 16 && ip[0]&0xfe == 0xfc
}

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

// AddrUpdateToAddr translates AddrUpdate struct to Addr.
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
