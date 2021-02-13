package conman

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netfilter"
	"github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/evilsocket/opensnitch/daemon/netstat"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"

	"github.com/google/gopacket/layers"
)

// Connection represents an outgoing connection.
type Connection struct {
	Protocol string
	SrcIP    net.IP
	SrcPort  uint
	DstIP    net.IP
	DstPort  uint
	DstHost  string
	Entry    *netstat.Entry
	Process  *procmon.Process

	pkt *netfilter.Packet
}

var showUnknownCons = false

// Parse extracts the IP layers from a network packet to determine what
// process generated a connection.
func Parse(nfp netfilter.Packet, interceptUnknown bool) *Connection {
	showUnknownCons = interceptUnknown

	if nfp.IsIPv4() {
		con, err := NewConnection(&nfp)
		if err != nil {
			log.Debug("%s", err)
			return nil
		} else if con == nil {
			return nil
		}
		return con
	}

	if core.IPv6Enabled == false {
		return nil
	}
	con, err := NewConnection6(&nfp)
	if err != nil {
		log.Debug("%s", err)
		return nil
	} else if con == nil {
		return nil
	}
	return con

}

func newConnectionImpl(nfp *netfilter.Packet, c *Connection, protoType string) (cr *Connection, err error) {
	// no errors but not enough info neither
	if c.parseDirection(protoType) == false {
		return nil, nil
	}
	log.Debug("new connection %s => %d:%v -> %v:%d uid: %d", c.Protocol, c.SrcPort, c.SrcIP, c.DstIP, c.DstPort, nfp.UID)

	c.Entry = &netstat.Entry{
		Proto:   c.Protocol,
		SrcIP:   c.SrcIP,
		SrcPort: c.SrcPort,
		DstIP:   c.DstIP,
		DstPort: c.DstPort,
		UserId:  -1,
		INode:   -1,
	}

	// 0. lookup uid and inode via netlink. Can return several inodes.
	// 1. lookup uid and inode using /proc/net/(udp|tcp|udplite)
	// 2. lookup pid by inode
	// 3. if this is coming from us, just accept
	// 4. lookup process info by pid
	uid, inodeList := netlink.GetSocketInfo(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
	if len(inodeList) == 0 {
		if c.Entry = netstat.FindEntry(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort); c.Entry == nil {
			return nil, fmt.Errorf("Could not find netstat entry for: %s", c)
		}
		if c.Entry.INode != -1 {
			inodeList = append([]int{c.Entry.INode}, inodeList...)
		}
	}
	if len(inodeList) == 0 {
		log.Debug("<== no inodes found, applying default action.")
		return nil, nil
	}

	if uid != -1 {
		c.Entry.UserId = uid
	} else if c.Entry.UserId == -1 && nfp.UID != 0xffffffff {
		c.Entry.UserId = int(nfp.UID)
	}

	pid := -1
	for n, inode := range inodeList {
		if pid = procmon.GetPIDFromINode(inode, fmt.Sprint(inode, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)); pid == os.Getpid() {
			// return a Process object with our PID, to be able to exclude our own connections
			// (to the UI on a local socket for example)
			c.Process = procmon.NewProcess(pid, "")
			return c, nil
		}
		if pid != -1 {
			log.Debug("[%d] PID found %d", n, pid)
			c.Entry.INode = inode
			break
		}
	}
	if c.Process = procmon.FindProcess(pid, showUnknownCons); c.Process == nil {
		return nil, fmt.Errorf("Could not find process by its pid %d for: %s", pid, c)
	}

	return c, nil

}

// NewConnection creates a new Connection object, and returns the details of it.
func NewConnection(nfp *netfilter.Packet) (c *Connection, err error) {
	ipv4 := nfp.Packet.Layer(layers.LayerTypeIPv4)
	if ipv4 == nil {
		return nil, errors.New("Error getting IPv4 layer")
	}
	ip, ok := ipv4.(*layers.IPv4)
	if !ok {
		return nil, errors.New("Error getting IPv4 layer data")
	}
	c = &Connection{
		SrcIP:   ip.SrcIP,
		DstIP:   ip.DstIP,
		DstHost: dns.HostOr(ip.DstIP, ""),
		pkt:     nfp,
	}
	return newConnectionImpl(nfp, c, "")
}

// NewConnection6 creates a IPv6 new Connection object, and returns the details of it.
func NewConnection6(nfp *netfilter.Packet) (c *Connection, err error) {
	ipv6 := nfp.Packet.Layer(layers.LayerTypeIPv6)
	if ipv6 == nil {
		return nil, errors.New("Error getting IPv6 layer")
	}
	ip, ok := ipv6.(*layers.IPv6)
	if !ok {
		return nil, errors.New("Error getting IPv6 layer data")
	}
	c = &Connection{
		SrcIP:   ip.SrcIP,
		DstIP:   ip.DstIP,
		DstHost: dns.HostOr(ip.DstIP, ""),
		pkt:     nfp,
	}
	return newConnectionImpl(nfp, c, "6")
}

func (c *Connection) parseDirection(protoType string) bool {
	ret := false
	if tcpLayer := c.pkt.Packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok == true && tcp != nil {
			c.Protocol = "tcp" + protoType
			c.DstPort = uint(tcp.DstPort)
			c.SrcPort = uint(tcp.SrcPort)
			ret = true

			if tcp.DstPort == 53 {
				c.getDomains(c.pkt, c)
			}
		}
	} else if udpLayer := c.pkt.Packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok == true && udp != nil {
			c.Protocol = "udp" + protoType
			c.DstPort = uint(udp.DstPort)
			c.SrcPort = uint(udp.SrcPort)
			ret = true

			if udp.DstPort == 53 {
				c.getDomains(c.pkt, c)
			}
		}
	} else if udpliteLayer := c.pkt.Packet.Layer(layers.LayerTypeUDPLite); udpliteLayer != nil {
		if udplite, ok := udpliteLayer.(*layers.UDPLite); ok == true && udplite != nil {
			c.Protocol = "udplite" + protoType
			c.DstPort = uint(udplite.DstPort)
			c.SrcPort = uint(udplite.SrcPort)
			ret = true
		}
	}

	return ret
}

func (c *Connection) getDomains(nfp *netfilter.Packet, con *Connection) {
	domains := dns.GetQuestions(nfp)
	if len(domains) > 0 {
		for _, dns := range domains {
			con.DstHost = dns
		}
	}
}

// To returns the destination host of a connection.
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

// Serialize returns a connection serialized.
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
		ProcessEnv:  c.Process.Env,
		ProcessCwd:  c.Process.CWD,
	}
}
