package netlink

import (
	"encoding/binary"
	"syscall"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// request:
// {nlmsg_len=36, nlmsg_type=SOCK_DIAG_BY_FAMILY, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=123456, nlmsg_pid=0},
// {sdiag_family=AF_PACKET, sdiag_protocol=0, pdiag_ino=0, pdiag_show=PACKET_SHOW_INFO, pdiag_cookie=[0, 0]}

// responses (depends on what filters are passed in the request):
// {pdiag_family=AF_PACKET, pdiag_type=SOCK_RAW, pdiag_num=ETH_P_ALL, pdiag_ino=257944535, pdiag_cookie=[1291434, 0]},
// {nla_len=28, nla_type=PACKET_DIAG_INFO},
// {pdi_index=if_nametoindex("wifi0"), pdi_version=TPACKET_V3, pdi_reserve=4, pdi_copy_thresh=0, pdi_tstamp=0, pdi_flags=PDI_RUNNING|PDI_AUXDATA}
// {nla_len=8, nla_type=PACKET_DIAG_UID}, 0}
// {nla_len=32, nla_type=PACKET_DIAG_RX_RING},
// {pdr_block_size=262144, pdr_block_nr=8, pdr_frame_size=262144, pdr_frame_nr=8, pdr_retire_tmo=10, pdr_sizeof_priv=0, pdr_features=0}
// {nla_len=40, nla_type=PACKET_DIAG_MEMINFO},
// [[SK_MEMINFO_RMEM_ALLOC]=0, [SK_MEMINFO_RCVBUF]=212992, [SK_MEMINFO_WMEM_ALLOC]=0, [SK_MEMINFO_SNDBUF]=212992, [SK_MEMINFO_FWD_ALLOC]=0, [SK_MEMINFO_WMEM_QUEUED]=0, [SK_MEMINFO_OPTMEM]=128, [SK_MEMINFO_BACKLOG]=0, [SK_MEMINFO_DROPS]=0]],
// {nla_len=12, nla_type=PACKET_DIAG_FILTER}, 0x512e76dfc140}

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/packet_diag.h#L16
// list of possible information to request
const (
	PACKET_SHOW_INFO     = 0x00000001 /* Basic packet_sk information */
	PACKET_SHOW_MCLIST   = 0x00000002 /* A set of packet_diag_mclist-s */
	PACKET_SHOW_RING_CFG = 0x00000004 /* Rings configuration parameters */
	PACKET_SHOW_FANOUT   = 0x00000008
	PACKET_SHOW_MEMINFO  = 0x00000010
	PACKET_SHOW_FILTER   = 0x00000020
)

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/packet_diag.h#L32
// types of messages retrieved from kernel
const (
	PACKET_DIAG_INFO = iota
	PACKET_DIAG_MCLIST
	PACKET_DIAG_RX_RING
	PACKET_DIAG_TX_RING
	PACKET_DIAG_FANOUT
	PACKET_DIAG_UID
	PACKET_DIAG_MEMINFO
	PACKET_DIAG_FILTER
)

const (
	sizePktDiagReq    = 20
	sizePktDiagMclist = 28
)

// PacketDiagMsg holds the message(s) sent by the kernel
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/packet_diag.h#L23
type PacketDiagMsg struct {
	Mclist PacketDiagMclist
	Cookie [2]uint32
	Inode  uint32
	UID    uint32
	Num    uint16 // ETH_P_ALL, etc
	Family uint8
	Type   uint8
}

// PacketDiagMclist struct
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/packet_diag.h#L63
type PacketDiagMclist struct {
	Index uint32
	Count uint32
	Type  uint16
	Alen  uint16
	Addr  [32]uint8 /* MAX_ADDR_LEN */
}

func (pm *PacketDiagMsg) deserialize(b []byte) error {
	rb := readBuffer{Bytes: b}

	// 1st message: PacketDiagMsg
	pm.Family = rb.Read()
	pm.Type = rb.Read()
	pm.Num = native.Uint16(rb.Next(2))
	pm.Inode = native.Uint32(rb.Next(4))
	pm.Cookie[0] = native.Uint32(rb.Next(4))
	pm.Cookie[1] = native.Uint32(rb.Next(4))

	nextMsg := rb.Read() // next msg size
	if nextMsg == sizePktDiagMclist {
		pm.Mclist = PacketDiagMclist{
			// XXX: wrong values with native.Uint32()
			Index: binary.BigEndian.Uint32(rb.Next(4)),
			Count: binary.BigEndian.Uint32(rb.Next(4)),
			Type:  binary.BigEndian.Uint16(rb.Next(2)),
			Alen:  binary.BigEndian.Uint16(rb.Next(2)),
		}
		copy(pm.Mclist.Addr[:], rb.Next(16))
	}

	// {nla_len=8, nla_type=PACKET_DIAG_UID}, 1000}
	nextMsg = rb.Read() // 8, size of next msg
	nextMsg = rb.Read() // pad?
	if nextMsg == PACKET_DIAG_UID {
		rb.Read() // pad?
		pm.UID = native.Uint32(rb.Next(4))
	}
	log.Trace("PktDiagMsg.deserialize (size: %d, sizeOf(PacketDiagMsg): %d): %+v", len(b), unsafe.Sizeof(b), pm)

	return nil
}

// PacketDiagReq struct to request data from the kernel
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/packet_diag.h#L7
type PacketDiagReq struct {
	Family   uint8
	Protocol uint8
	Pad      uint16
	Inode    uint32
	Show     uint32
	Cookie   [2]uint32
}

// Serialize ...
func (p *PacketDiagReq) Serialize() []byte {
	b := writeBuffer{Bytes: make([]byte, sizePktDiagReq)}
	b.Write(p.Family)
	b.Write(p.Protocol)
	native.PutUint16(b.Next(2), p.Pad)
	native.PutUint32(b.Next(4), p.Inode)
	native.PutUint32(b.Next(4), p.Show)
	native.PutUint32(b.Next(4), p.Cookie[0])
	native.PutUint32(b.Next(4), p.Cookie[1])

	return b.Bytes
}

// Len ...
func (p *PacketDiagReq) Len() int { return sizePktDiagReq }

// SocketDiagPacket dumps AF_PACKET sockets from kernel
func SocketDiagPacket(proto uint8) ([]*PacketDiagMsg, error) {
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, syscall.NLM_F_DUMP)
	req.AddData(&PacketDiagReq{
		Family:   unix.AF_PACKET,
		Protocol: proto,
		// TODO: dump bpf filters  | PACKET_SHOW_FILTER
		Show: PACKET_SHOW_INFO | PACKET_SHOW_MCLIST,
	})
	msgs, err := req.Execute(syscall.NETLINK_INET_DIAG, 0)
	if err != nil {
		log.Debug("[netlink] socket.packetRequest: %s", err)
		return nil, err
	}
	if len(msgs) == 0 {
		log.Debug("[netlink] socket.packetRequest: 0 msgs")
		return []*PacketDiagMsg{}, nil
	}

	pkts := make([]*PacketDiagMsg, len(msgs))
	for n, m := range msgs {
		log.Trace("[netlink] AF_PACKET, size: %d, %+v", len(m), m)
		p := &PacketDiagMsg{}
		if err = p.deserialize(m); err != nil {
			log.Trace("[%d] netlink socket.packet error: %s", n, err)
			continue
		}
		pkts[n] = p
	}
	return pkts, nil
}
