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
	lock      = sync.RWMutex{}
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
		if ans.Name != nil {
			if ans.IP != nil {
				Track(ans.IP.String(), string(ans.Name))
			} else if ans.CNAME != nil {
				Track(string(ans.CNAME), string(ans.Name))
			}
		}
	}

	return true
}

func Track(resolved string, hostname string) {
	lock.Lock()
	defer lock.Unlock()

	responses[resolved] = hostname

	log.Debug("New DNS record: %s -> %s", resolved, hostname)
}

func Host(resolved string) (host string, found bool) {
	lock.RLock()
	defer lock.RUnlock()

	host, found = responses[resolved]
	return
}

func HostOr(ip net.IP, or string) string {
	if host, found := Host(ip.String()); found == true {
		// host might have been CNAME; go back until we reach the "root"
		seen := make(map[string]bool) // prevent possibility of loops
		for {
			orig, had := Host(host)
			if seen[orig] {
				break
			}
			if !had {
				break
			}
			seen[orig] = true
			host = orig
		}
		return host
	}
	return or
}
