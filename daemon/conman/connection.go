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
	"github.com/evilsocket/opensnitch/daemon/procmon/audit"
	"github.com/evilsocket/opensnitch/daemon/procmon/ebpf"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"

	"github.com/google/gopacket/layers"
)

// Connection represents an outgoing connection.
type Connection struct {
	Pkt     *netfilter.Packet
	Entry   *netstat.Entry
	Process *procmon.Process

	Protocol string
	DstHost  string
	SrcIP    net.IP
	DstIP    net.IP

	SrcPort uint
	DstPort uint
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
		log.Debug("discarding conn: %+v", c)
		return nil, nil
	}
	log.Debug("new connection %s => %d:%v -> %v (%s):%d uid: %d, mark: %x", c.Protocol, c.SrcPort, c.SrcIP, c.DstIP, c.DstHost, c.DstPort, nfp.UID, nfp.Mark)

	c.Entry = &netstat.Entry{
		Proto:   c.Protocol,
		SrcIP:   c.SrcIP,
		SrcPort: c.SrcPort,
		DstIP:   c.DstIP,
		DstPort: c.DstPort,
		UserId:  -1,
		INode:   -1,
	}

	pid := -1
	uid := -1
	if procmon.MethodIsEbpf() {
		swap := false
		c.Process, swap, err = ebpf.GetPid(c.Protocol, c.SrcPort, c.SrcIP, c.DstIP, c.DstPort)
		if swap {
			c.swapFields()
		}

		if c.Process != nil {
			c.Entry.UserId = c.Process.UID
			return c, nil
		}
		if err != nil {
			log.Debug("ebpf warning: %v", err)
		}
		log.Debug("[ebpf conn] PID not found via eBPF, falling back to proc")
	} else if procmon.MethodIsAudit() {
		if aevent := audit.GetEventByPid(pid); aevent != nil {
			audit.Lock.RLock()
			c.Process = procmon.NewProcessEmpty(pid, aevent.ProcName)
			c.Process.Path = aevent.ProcPath
			c.Process.ReadCmdline()
			c.Process.CWD = aevent.ProcDir
			audit.Lock.RUnlock()
			// if the proc dir contains non alhpa-numeric chars the field is empty
			if c.Process.CWD == "" {
				c.Process.ReadCwd()
			}
			c.Process.ReadEnv()
			c.Process.CleanPath()

			procmon.EventsCache.Add(c.Process)
			return c, nil
		}
		log.Debug("[auditd conn] PID not found via auditd, falling back to proc")
	}

	// Sometimes when using eBPF, the PID is not found by the connection's parameters,
	// but falling back to legacy methods helps to find it and avoid "unknown/kernel pop-ups".
	//
	// One of the reasons is because after coming back from suspend state, for some reason (bug?),
	// gobpf/libbpf is unable to delete ebpf map entries, so when they reach the maximum capacity no
	// more entries are added, nor updated.
	if pid < 0 {
		// 0. lookup uid and inode via netlink. Can return several inodes.
		// 1. lookup uid and inode using /proc/net/(udp|tcp|udplite)
		// 2. lookup pid by inode
		// 3. if this is coming from us, just accept
		// 4. lookup process info by pid
		var inodeList []int
		uid, inodeList = netlink.GetSocketInfo(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
		if len(inodeList) == 0 {
			procmon.GetInodeFromNetstat(c.Entry, &inodeList, c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
		}

		for n, inode := range inodeList {
			pid = procmon.GetPIDFromINode(inode, fmt.Sprint(inode, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort))
			if pid != -1 {
				log.Debug("[%d] PID found %d [%d]", n, pid, inode)
				c.Entry.INode = inode
				break
			}
		}
	}

	if pid == os.Getpid() {
		// return a Process object with our PID, to be able to exclude our own connections
		// (to the UI on a local socket for example)
		c.Process = procmon.NewProcessEmpty(pid, "")
		return c, nil
	}

	if nfp.UID != 0xffffffff {
		uid = int(nfp.UID)
	}
	c.Entry.UserId = uid

	if c.Process == nil {
		if c.Process = procmon.FindProcess(pid, showUnknownCons); c.Process == nil {
			return nil, fmt.Errorf("Could not find process by its pid %d for: %s", pid, c)
		}
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
		Pkt:     nfp,
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
		Pkt:     nfp,
	}
	return newConnectionImpl(nfp, c, "6")
}

func (c *Connection) parseDirection(protoType string) bool {
	ret := false
	if tcpLayer := c.Pkt.Packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok == true && tcp != nil {
			c.Protocol = "tcp" + protoType
			c.DstPort = uint(tcp.DstPort)
			c.SrcPort = uint(tcp.SrcPort)
			ret = true

			if tcp.DstPort == 53 {
				c.getDomains(c.Pkt, c)
			}
		}
	} else if udpLayer := c.Pkt.Packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok == true && udp != nil {
			c.Protocol = "udp" + protoType
			c.DstPort = uint(udp.DstPort)
			c.SrcPort = uint(udp.SrcPort)
			ret = true

			if udp.DstPort == 53 {
				c.getDomains(c.Pkt, c)
			}
		}
	} else if udpliteLayer := c.Pkt.Packet.Layer(layers.LayerTypeUDPLite); udpliteLayer != nil {
		if udplite, ok := udpliteLayer.(*layers.UDPLite); ok == true && udplite != nil {
			c.Protocol = "udplite" + protoType
			c.DstPort = uint(udplite.DstPort)
			c.SrcPort = uint(udplite.SrcPort)
			ret = true
		}
	} else if sctpLayer := c.Pkt.Packet.Layer(layers.LayerTypeSCTP); sctpLayer != nil {
		if sctp, ok := sctpLayer.(*layers.SCTP); ok == true && sctp != nil {
			c.Protocol = "sctp" + protoType
			c.DstPort = uint(sctp.DstPort)
			c.SrcPort = uint(sctp.SrcPort)
			ret = true
		}
	} else if icmpLayer := c.Pkt.Packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		if icmp, ok := icmpLayer.(*layers.ICMPv4); ok == true && icmp != nil {
			c.Protocol = "icmp"
			c.DstPort = 0
			c.SrcPort = 0
			ret = true
		}
	} else if icmp6Layer := c.Pkt.Packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		if icmp6, ok := icmp6Layer.(*layers.ICMPv6); ok == true && icmp6 != nil {
			c.Protocol = "icmp" + protoType
			c.DstPort = 0
			c.SrcPort = 0
			ret = true
		}
	}

	return ret
}

// swapFields swaps connection's fields.
// Used to workaround an issue where outbound connections
// have the fields swapped (procmon/ebpf/find.go).
func (c *Connection) swapFields() {
	oEntry := c.Entry
	c.Entry = &netstat.Entry{
		Proto:   c.Protocol,
		SrcIP:   oEntry.DstIP,
		DstIP:   oEntry.SrcIP,
		SrcPort: oEntry.DstPort,
		DstPort: oEntry.SrcPort,
		UserId:  oEntry.UserId,
		INode:   oEntry.INode,
	}
	c.SrcIP = oEntry.DstIP
	c.DstIP = oEntry.SrcIP
	c.DstPort = oEntry.SrcPort
	c.SrcPort = oEntry.DstPort
}

func (c *Connection) getDomains(nfp *netfilter.Packet, con *Connection) {
	domains := dns.GetQuestions(nfp)
	if len(domains) < 1 {
		return
	}
	for _, dns := range domains {
		con.DstHost = dns
	}
}

// To returns the destination host of a connection.
func (c *Connection) To() string {
	if c.DstHost == "" {
		return c.DstIP.String()
	}
	return fmt.Sprintf("%s (%s)", c.DstHost, c.DstIP)
}

func (c *Connection) String() string {
	if c.Entry == nil {
		return fmt.Sprintf("%d:%s ->(%s)-> %s:%d", c.SrcPort, c.SrcIP, c.Protocol, c.To(), c.DstPort)
	}

	if c.Process == nil {
		return fmt.Sprintf("%d:%s (uid:%d) ->(%s)-> %s:%d", c.SrcPort, c.SrcIP, c.Entry.UserId, c.Protocol, c.To(), c.DstPort)
	}

	return fmt.Sprintf("%s (%d) -> %s:%d (proto:%s uid:%d)", c.Process.Path, c.Process.ID, c.To(), c.DstPort, c.Protocol, c.Entry.UserId)
}

// Serialize returns a connection serialized.
func (c *Connection) Serialize() *protocol.Connection {
	c.Process.RLock()
	defer c.Process.RUnlock()
	return &protocol.Connection{
		Protocol:         c.Protocol,
		SrcIp:            c.SrcIP.String(),
		SrcPort:          uint32(c.SrcPort),
		DstIp:            c.DstIP.String(),
		DstHost:          c.DstHost,
		DstPort:          uint32(c.DstPort),
		UserId:           uint32(c.Entry.UserId),
		ProcessId:        uint32(c.Process.ID),
		ProcessPath:      c.Process.Path,
		ProcessArgs:      c.Process.Args,
		ProcessEnv:       c.Process.Env,
		ProcessCwd:       c.Process.CWD,
		ProcessChecksums: c.Process.Checksums,
		ProcessTree:      c.Process.Tree,
	}
}
