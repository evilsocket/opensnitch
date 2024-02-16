package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/vishvananda/netlink/nl"
)

// This is a modification of https://github.com/vishvananda/netlink socket_linux.go - Apache2.0 license
// which adds support for query UDP, UDPLITE and IPv6 sockets to SocketGet()

const (
	SOCK_DESTROY        = 21
	sizeofSocketID      = 0x30
	sizeofSocketRequest = sizeofSocketID + 0x8
	sizeofSocket        = sizeofSocketID + 0x18
)

var (
	native       = nl.NativeEndian()
	networkOrder = binary.BigEndian
	TCP_ALL      = uint32(0xfff)
)

// https://elixir.bootlin.com/linux/latest/source/include/net/tcp_states.h
const (
	TCP_INVALID = iota
	TCP_ESTABLISHED
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING
	TCP_NEW_SYN_REC
	TCP_MAX_STATES
)

// TCPStatesMap holds the list of TCP states
var TCPStatesMap = map[uint8]string{
	TCP_INVALID:     "invalid",
	TCP_ESTABLISHED: "established",
	TCP_SYN_SENT:    "syn_sent",
	TCP_SYN_RECV:    "syn_recv",
	TCP_FIN_WAIT1:   "fin_wait1",
	TCP_FIN_WAIT2:   "fin_wait2",
	TCP_TIME_WAIT:   "time_wait",
	TCP_CLOSE:       "close",
	TCP_CLOSE_WAIT:  "close_wait",
	TCP_LAST_ACK:    "last_ack",
	TCP_LISTEN:      "listen",
	TCP_CLOSING:     "closing",
}

// SocketID holds the socket information of a request/response to the kernel
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
	UID     uint32
	INode   uint32
}

// SocketRequest holds the request/response of a connection to the kernel
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

// Serialize convert SocketRequest struct to bytes.
func (r *SocketRequest) Serialize() []byte {
	b := writeBuffer{Bytes: make([]byte, sizeofSocketRequest)}
	b.Write(r.Family)
	b.Write(r.Protocol)
	b.Write(r.Ext)
	b.Write(r.pad)
	native.PutUint32(b.Next(4), r.States)
	networkOrder.PutUint16(b.Next(2), r.ID.SourcePort)
	networkOrder.PutUint16(b.Next(2), r.ID.DestinationPort)
	if r.Family == syscall.AF_INET6 {
		copy(b.Next(16), r.ID.Source)
		copy(b.Next(16), r.ID.Destination)
	} else {
		copy(b.Next(4), r.ID.Source.To4())
		b.Next(12)
		copy(b.Next(4), r.ID.Destination.To4())
		b.Next(12)
	}
	native.PutUint32(b.Next(4), r.ID.Interface)
	native.PutUint32(b.Next(4), r.ID.Cookie[0])
	native.PutUint32(b.Next(4), r.ID.Cookie[1])
	return b.Bytes
}

// Len returns the size of a socket request
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
	if s.Family == syscall.AF_INET6 {
		s.ID.Source = net.IP(rb.Next(16))
		s.ID.Destination = net.IP(rb.Next(16))
	} else {
		s.ID.Source = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
		s.ID.Destination = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
	}
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

// SocketKill kills a connection
func SocketKill(family, proto uint8, sockID SocketID) error {

	sockReq := &SocketRequest{
		Family:   family,
		Protocol: proto,
		ID:       sockID,
	}

	req := nl.NewNetlinkRequest(SOCK_DESTROY, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	req.AddData(sockReq)
	_, err := req.Execute(syscall.NETLINK_INET_DIAG, 0)
	if err != nil {
		return err
	}
	return nil
}

// SocketGet returns the list of active connections in the kernel
// filtered by several fields. Currently it returns connections
// filtered by source port and protocol.
func SocketGet(family uint8, proto uint8, srcPort, dstPort uint16, local, remote net.IP) ([]*Socket, error) {
	_Id := SocketID{
		SourcePort: srcPort,
		Cookie:     [2]uint32{nl.TCPDIAG_NOCOOKIE, nl.TCPDIAG_NOCOOKIE},
	}

	sockReq := &SocketRequest{
		Family:   family,
		Protocol: proto,
		States:   TCP_ALL,
		ID:       _Id,
	}

	return netlinkRequest(sockReq, family, proto, srcPort, dstPort, local, remote)
}

// SocketsDump returns the list of all connections from the kernel
func SocketsDump(family uint8, proto uint8) ([]*Socket, error) {
	sockReq := &SocketRequest{
		Family:   family,
		Protocol: proto,
		States:   TCP_ALL,
	}
	return netlinkRequest(sockReq, 0, 0, 0, 0, nil, nil)
}

func netlinkRequest(sockReq *SocketRequest, family uint8, proto uint8, srcPort, dstPort uint16, local, remote net.IP) ([]*Socket, error) {
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, syscall.NLM_F_DUMP)
	req.AddData(sockReq)
	msgs, err := req.Execute(syscall.NETLINK_INET_DIAG, 0)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, errors.New("Warning, no message nor error from netlink, or no connections found")
	}
	var sock []*Socket
	for n, m := range msgs {
		s := &Socket{}
		if err = s.deserialize(m); err != nil {
			log.Error("[%d] netlink socket error: %s, %d:%v -> %v:%d -  %d:%v -> %v:%d",
				n, TCPStatesMap[s.State],
				srcPort, local, remote, dstPort,
				s.ID.SourcePort, s.ID.Source, s.ID.Destination, s.ID.DestinationPort)
			continue
		}
		if s.INode == 0 {
			continue
		}

		sock = append([]*Socket{s}, sock...)
	}
	return sock, err
}
