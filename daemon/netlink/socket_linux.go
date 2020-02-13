package netlink

import (
	"errors"
	"fmt"
	"net"
	"encoding/binary"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// This is a copy of https://github.com/vishvananda/netlink socket_linux.go
// which adds support for query UDP, UDPLITE and IPv6 sockets

const (
	sizeofSocketID      = 0x30
	sizeofSocketRequest = sizeofSocketID + 0x8
	sizeofSocket        = sizeofSocketID + 0x18
)

var (
	ErrNotImplemented = errors.New("not implemented")
	native	   = nl.NativeEndian()
	networkOrder = binary.BigEndian
	TCP_ALL = uint32(0xfff)
)

type SocketID struct {
	SourcePort      uint16
	DestinationPort uint16
	Source          net.IP
	Destination     net.IP
	Interface       uint32
	Cookie          [2]uint32
}

// Socket represents a netlink socket.
type Socket struct {
	Family  uint8
	State   uint8
	Timer   uint8
	Retrans uint8
	ID      SocketID
	Expires uint32
	RQueue  uint32
	WQueue  uint32
	UID	uint32
	INode   uint32
}

type SocketRequest struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	pad      uint8
	States   uint32
	ID       SocketID
}

type writeBuffer struct {
	Bytes []byte
	pos   int
}

func (b *writeBuffer) Write(c byte) {
	b.Bytes[b.pos] = c
	b.pos++
}

func (b *writeBuffer) Next(n int) []byte {
	s := b.Bytes[b.pos : b.pos+n]
	b.pos += n
	return s
}

func (r *SocketRequest) Serialize() []byte {
	b := writeBuffer{Bytes: make([]byte, sizeofSocketRequest)}
	b.Write(r.Family)
	b.Write(r.Protocol)
	b.Write(r.Ext)
	b.Write(r.pad)
	native.PutUint32(b.Next(4), r.States)
	networkOrder.PutUint16(b.Next(2), r.ID.SourcePort)
	networkOrder.PutUint16(b.Next(2), r.ID.DestinationPort)
	copy(b.Next(4), r.ID.Source.To4())
	b.Next(12)
	copy(b.Next(4), r.ID.Destination.To4())
	b.Next(12)
	native.PutUint32(b.Next(4), r.ID.Interface)
	native.PutUint32(b.Next(4), r.ID.Cookie[0])
	native.PutUint32(b.Next(4), r.ID.Cookie[1])
	return b.Bytes
}

func (r *SocketRequest) Len() int { return sizeofSocketRequest }

type readBuffer struct {
	Bytes []byte
	pos   int
}

func (b *readBuffer) Read() byte {
	c := b.Bytes[b.pos]
	b.pos++
	return c
}

func (b *readBuffer) Next(n int) []byte {
	s := b.Bytes[b.pos : b.pos+n]
	b.pos += n
	return s
}

func (s *Socket) deserialize(b []byte) error {
	if len(b) < sizeofSocket {
		return fmt.Errorf("socket data short read (%d); want %d", len(b), sizeofSocket)
	}
	rb := readBuffer{Bytes: b}
	s.Family = rb.Read()
	s.State = rb.Read()
	s.Timer = rb.Read()
	s.Retrans = rb.Read()
	s.ID.SourcePort = networkOrder.Uint16(rb.Next(2))
	s.ID.DestinationPort = networkOrder.Uint16(rb.Next(2))
	s.ID.Source = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
	rb.Next(12)
	s.ID.Destination = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
	rb.Next(12)
	s.ID.Interface = native.Uint32(rb.Next(4))
	s.ID.Cookie[0] = native.Uint32(rb.Next(4))
	s.ID.Cookie[1] = native.Uint32(rb.Next(4))
	s.Expires = native.Uint32(rb.Next(4))
	s.RQueue = native.Uint32(rb.Next(4))
	s.WQueue = native.Uint32(rb.Next(4))
	s.UID = native.Uint32(rb.Next(4))
	s.INode = native.Uint32(rb.Next(4))
	return nil
}

// SocketGet returns the Socket identified by its local and remote addresses.
func SocketGet(family uint8, proto uint8, local, remote net.Addr) (*Socket, error) {
	var sPort, dPort uint16
	var localIP, remoteIP net.IP
	_Id := SocketID{}

	if proto == unix.IPPROTO_UDP || proto == unix.IPPROTO_UDPLITE {
		localUDP, ok := local.(*net.UDPAddr)
		if !ok {
			return nil, errors.New ("UDP IP error: invalid source IP")
		}
		remoteUDP, ok := remote.(*net.UDPAddr)
		if !ok {
			return nil, errors.New ("UDP IP error: invalid remote IP")
		}
		if family == unix.AF_INET6 {
			localIP = localUDP.IP.To16()
			remoteIP = remoteUDP.IP.To16()
		} else {
			localIP = localUDP.IP.To4()
			remoteIP = remoteUDP.IP.To4()
		}

		sPort = uint16(localUDP.Port)
		dPort = uint16(remoteUDP.Port)
	} else {
		localTCP, ok := local.(*net.TCPAddr)
		if !ok {
			return nil, errors.New ("TCP IP error: invalid source IP")
		}
		remoteTCP, ok := remote.(*net.TCPAddr)
		if !ok {
			return nil, errors.New ("TCP IP error: invalid remote IP")
		}
		if family == unix.AF_INET6 {
			localIP = localTCP.IP.To16()
			remoteIP = remoteTCP.IP.To16()
		} else {
			localIP = localTCP.IP.To4()
			remoteIP = remoteTCP.IP.To4()
		}

		sPort = uint16(localTCP.Port)
		dPort = uint16(remoteTCP.Port)
	}

	_Id = SocketID{
		SourcePort:			sPort,
		DestinationPort:	dPort,
		Source:				localIP,
		Destination:		remoteIP,
		Cookie:				[2]uint32{nl.TCPDIAG_NOCOOKIE, nl.TCPDIAG_NOCOOKIE},
	}
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, 0)
	req.AddData(&SocketRequest{
		Family:   family,
		Protocol: proto,
		States:   uint32(TCP_ALL),
		ID: _Id,
	})
	msgs, err := req.Execute(syscall.NETLINK_INET_DIAG, 0)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, errors.New("no message nor error from netlink")
	}
	if len(msgs) > 2 {
		return nil, fmt.Errorf("multiple (%d) matching sockets", len(msgs))
	}
	sock := &Socket{}
	if err := sock.deserialize(msgs[0]); err != nil {
		return nil, err
	}
	return sock, nil
}
