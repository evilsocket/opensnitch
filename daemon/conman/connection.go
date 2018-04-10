package conman

import (
	"fmt"
	"net"
	"os"

	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netfilter"
	"github.com/evilsocket/opensnitch/daemon/netstat"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"

	"github.com/google/gopacket/layers"
)

type Connection struct {
	Protocol string
	SrcIP    net.IP
	SrcPort  int
	DstIP    net.IP
	DstPort  int
	DstHost  string
	Entry    *netstat.Entry
	Process  *procmon.Process

	pkt *netfilter.Packet
}

func Parse(nfp netfilter.Packet) *Connection {
	ipLayer := nfp.Packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ip, ok := ipLayer.(*layers.IPv4)
	if ok == false || ip == nil {
		return nil
	}

	// we're not interested in connections
	// from/to the localhost interface
	if ip.SrcIP.IsLoopback() {
		return nil
	}

	// skip multicast stuff
	if ip.SrcIP.IsMulticast() || ip.DstIP.IsMulticast() {
		return nil
	}

	// skip broadcasted stuff
	// FIXME: this is ugly
	if ip.DstIP[3] == 0xff {
		return nil
	}

	con, err := NewConnection(&nfp, ip)
	if err != nil {
		log.Debug("%s", err)
		return nil
	} else if con == nil {
		return nil
	}

	return con
}

func (c *Connection) checkLayers() bool {
	for _, layer := range c.pkt.Packet.Layers() {
		if layer.LayerType() == layers.LayerTypeTCP {
			if tcp, ok := layer.(*layers.TCP); ok == true && tcp != nil {
				c.Protocol = "tcp"
				c.DstPort = int(tcp.DstPort)
				c.SrcPort = int(tcp.SrcPort)
				return true
			}
		} else if layer.LayerType() == layers.LayerTypeUDP {
			if udp, ok := layer.(*layers.UDP); ok == true && udp != nil {
				c.Protocol = "udp"
				c.DstPort = int(udp.DstPort)
				c.SrcPort = int(udp.SrcPort)
				return true
			}
		}
	}

	return false
}

func NewConnection(nfp *netfilter.Packet, ip *layers.IPv4) (c *Connection, err error) {
	c = &Connection{
		SrcIP:   ip.SrcIP,
		DstIP:   ip.DstIP,
		DstHost: dns.HostOr(ip.DstIP, ""),
		pkt:     nfp,
	}

	// no errors but not enough info neither
	if c.checkLayers() == false {
		return nil, nil
	}

	// Lookup uid and inode using /proc/net/(udp|tcp)
	if c.Entry = netstat.FindEntry(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort); c.Entry == nil {
		return nil, fmt.Errorf("Could not find netstat entry for: %s", c)
	}

	// snapshot a map of: inode -> pid
	sockets := procmon.GetOpenSockets()
	// lookup pid by inode and process by pid
	if pid, found := sockets[c.Entry.INode]; found == false {
		return nil, fmt.Errorf("Could not find process id for: %s", c)
	} else if pid == os.Getpid() {
		return nil, nil
	} else if c.Process = procmon.FindProcess(pid); c.Process == nil {
		return nil, fmt.Errorf("Could not find process by its pid %d for: %s", pid, c)
	}

	return c, nil
}

func (c *Connection) To() string {
	if c.DstHost == "" {
		return c.DstIP.String()
	}
	return c.DstHost
}

func (c *Connection) String() string {
	if c.Entry == nil {
		return fmt.Sprintf("%s ->(%s)-> %s:%d", c.SrcIP, c.Protocol, c.To(), c.DstPort)
	}

	if c.Process == nil {
		return fmt.Sprintf("%s (uid:%d) ->(%s)-> %s:%d", c.SrcIP, c.Entry.UserId, c.Protocol, c.To(), c.DstPort)
	}

	return fmt.Sprintf("%s (%d) -> %s:%d (proto:%s uid:%d)", c.Process.Path, c.Process.ID, c.To(), c.DstPort, c.Protocol, c.Entry.UserId)
}

func (c *Connection) Serialize() *protocol.Connection {
	return &protocol.Connection{
		Protocol:    c.Protocol,
		SrcIp:       c.SrcIP.String(),
		SrcPort:     uint32(c.SrcPort),
		DstIp:       c.DstIP.String(),
		DstHost:     c.DstHost,
		DstPort:     uint32(c.DstPort),
		UserId:      uint32(c.Entry.UserId),
		ProcessId:   uint32(c.Process.ID),
		ProcessPath: c.Process.Path,
		ProcessArgs: c.Process.Args,
	}
}
