package socketsmonitor

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/log"
	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/evilsocket/opensnitch/daemon/procmon"
)

const (
	// AnySocket constant indicates that we should return all sockets found.
	// If the user selected a socket type, family or protocol, the value will be > 0
	AnySocket = 0
)

// Socket represents every socket dumped from the kernel for the given filter.
type Socket struct {
	Socket *daemonNetlink.Socket
	Iface  string
	PID    int
	Mark   uint32
	Proto  uint8
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

		sockList, err := daemonNetlink.SocketsDump(opt.Fam, opt.Proto)
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
			go addSocketToTable(pm.Ctx, &wg, opt.Proto, socketList, *sock)
		}
		wg.Wait()
	}

	return socketList
}

func exclude(expected, what uint8) bool {
	return expected > AnySocket && expected != what
}

func addSocketToTable(ctx context.Context, wg *sync.WaitGroup, proto uint8, st *SocketsTable, s daemonNetlink.Socket) {
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
