package socketsmonitor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/evilsocket/opensnitch/daemon/netstat"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"golang.org/x/sys/unix"
)

const (
	// AnySocket constant indicates that we should return all sockets found.
	// If the user selected a socket type, family or protocol, the value will be > 0
	AnySocket = 0
)

// Socket represents every socket dumped from the kernel for the given filter.
// Internal to this package, and sent to the GUI as JSON.
type Socket struct {
	Socket *netlink.Socket
	Iface  string
	PID    int
	Mark   uint32
	Proto  uint16
}

// SocketsTable holds all the dumped sockets, after applying the filters, if any.
type SocketsTable struct {
	sync.RWMutex `json:"-"`
	Table        []*Socket
	Processes    map[int]*procmon.Process
}

func (pm *SocketsMonitor) dumpSockets() *SocketsTable {
	socketList := &SocketsTable{}
	socketList.Table = make([]*Socket, 0)
	socketList.Processes = make(map[int]*procmon.Process, 0)

	for n, opt := range options {
		if exclude(pm.Config.Family, opt.Fam) {
			continue
		}
		if exclude(pm.Config.Proto, opt.Proto) {
			continue
		}

		sockList, err := netlink.SocketsDump(opt.Fam, opt.Proto)
		if err != nil {
			log.Debug("[sockmon][%d] fam: %d, proto: %d, error: %s", n, opt.Fam, opt.Proto, err)
			continue
		}
		if len(sockList) == 0 {
			log.Debug("[sockmon][%d] fam: %d, proto: %d, no sockets: %d", n, opt.Fam, opt.Proto, opt.Proto)
			continue
		}

		var wg sync.WaitGroup
		for _, sock := range sockList {
			if sock == nil {
				continue
			}
			if exclude(pm.Config.State, sock.State) {
				continue
			}
			wg.Add(1)
			// XXX: firing a goroutine per socket may be too much on some scenarios
			go addSocketToTable(pm.Ctx, &wg, uint16(opt.Proto), socketList, *sock)
		}
		wg.Wait()
	}

	dumpXDPSockets(pm.Ctx, pm.Config, socketList)
	dumpPacketSockets(pm.Ctx, pm.Config, socketList)

	return socketList
}

func dumpXDPSockets(ctx context.Context, conf *monConfig, socketList *SocketsTable) {
	if exclude(conf.Family, unix.AF_XDP) && exclude(conf.Proto, syscall.IPPROTO_RAW) {
		return
	}
	xdpList, err := netlink.SocketGetXDP()
	if err != nil {
		return
	}
	var wg sync.WaitGroup
	for _, xdp := range xdpList {
		s := netlink.Socket{}
		s.Family = unix.AF_XDP
		s.INode = uint32(xdp.XDPDiagMsg.Ino)
		s.UID = uint32(xdp.XDPInfo.UID)
		s.ID = netlink.SocketID{
			Interface: xdp.XDPInfo.Ifindex,
			Cookie:    xdp.XDPDiagMsg.Cookie,
		}
		wg.Add(1)
		go addSocketToTable(ctx, &wg, syscall.IPPROTO_RAW, socketList, s)
	}
	wg.Wait()
}

func dumpPacketSockets(ctx context.Context, conf *monConfig, socketList *SocketsTable) {
	if exclude(conf.Family, unix.AF_PACKET) {
		return
	}
	var wg sync.WaitGroup

	pktList, err := netlink.SocketDiagPacket(0)
	for _, pkt := range pktList {
		/*if excludePacket(pm.Config.Proto, pkt.Num) {
			continue
		}*/

		s := netlink.Socket{}
		s.Family = unix.AF_PACKET
		s.INode = uint32(pkt.Inode)
		s.UID = uint32(pkt.UID)
		s.ID = netlink.SocketID{
			Interface: uint32(pkt.Mclist.Index),
			Cookie:    pkt.Cookie,
		}
		wg.Add(1)
		go addSocketToTable(ctx, &wg, pkt.Num /* proto */, socketList, s)
	}
	wg.Wait()

	if err == nil {
		return
	}

	// dumping AF_PACKET from kernel failed. Try it with /proc
	entries, err := netstat.ParsePacket()
	if err != nil {
		return
	}

	pktEntr := make(map[int]struct{}, len(entries))
	for n, e := range entries {
		if _, isDup := pktEntr[n]; isDup {
			continue
		}
		pktEntr[n] = struct{}{}

		/*if excludePacket(conf.Proto, opt.Proto) {
			continue
		}*/
		s := netlink.Socket{}
		s.Family = unix.AF_PACKET
		s.INode = uint32(e.INode)
		s.UID = uint32(e.UserId)
		s.ID = netlink.SocketID{
			Interface: uint32(e.Iface),
		}
		// TODO: report sock type
		wg.Add(1)
		go addSocketToTable(ctx, &wg, syscall.IPPROTO_RAW, socketList, s)
	}
	wg.Wait()
}

func exclude(expected, what uint8) bool {
	return expected > AnySocket && expected != what
}

func addSocketToTable(ctx context.Context, wg *sync.WaitGroup, proto uint16, st *SocketsTable, s netlink.Socket) {
	inode := int(s.INode)
	pid := procmon.GetPIDFromINode(inode, fmt.Sprint(inode,
		s.ID.Source, s.ID.SourcePort, s.ID.Destination, s.ID.DestinationPort),
	)
	// pid can be -1 in some scenarios (tor socket in FIN_WAIT1 state).
	// we could lookup the connection in the ebpfCache of connections.
	st.Lock()
	var p *procmon.Process
	if pid == -1 {
		p = &procmon.Process{}
	} else {
		if pp, found := st.Processes[pid]; !found {
			p = procmon.FindProcess(pid, false)
		} else {
			p = pp
		}
	}
	// XXX: should we assume that if the PID is in cache, it has already been sent to the GUI (server)?
	ss := &Socket{}
	ss.Socket = &s
	ss.PID = pid
	ss.Proto = proto
	if iface, err := net.InterfaceByIndex(int(s.ID.Interface)); err == nil {
		ss.Iface = iface.Name
	}

	st.Table = append(st.Table, ss)
	st.Processes[pid] = p
	st.Unlock()

	wg.Done()
}
