package dns

import (
	"net"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	responses = make(map[string]string, 0)
	lock      = sync.Mutex{}
)

func TrackAnswers(packet gopacket.Packet) bool {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return false
	}

	udp, ok := udpLayer.(*layers.UDP)
	if ok == false || udp == nil {
		return false
	}

	if udp.SrcPort != 53 {
		return false
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return false
	}

	dnsAns, ok := dnsLayer.(*layers.DNS)
	if ok == false || dnsAns == nil {
		return false
	}

	for _, ans := range dnsAns.Answers {
		if ans.Name != nil && ans.IP != nil {
			Track(ans.IP, string(ans.Name))
		}
	}

	return true
}

func Track(ip net.IP, hostname string) {
	address := ip.String()

	lock.Lock()
	defer lock.Unlock()

	responses[address] = hostname

	log.Debug("New DNS record: %s -> %s", address, hostname)
}

func Host(ip net.IP) (host string, found bool) {
	address := ip.String()

	lock.Lock()
	defer lock.Unlock()

	host, found = responses[address]
	return
}

func HostOr(ip net.IP, or string) string {
	if host, found := Host(ip); found == true {
		return host
	}
	return or
}
