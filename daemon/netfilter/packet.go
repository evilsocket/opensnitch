package netfilter

import "C"

import (
	"github.com/google/gopacket"
)

// packet consts
const (
	IPv4 = 4
)

// Verdict holds the action to perform on a packet (NF_DROP, NF_ACCEPT, etc)
type Verdict C.uint

// VerdictContainer struct
type VerdictContainer struct {
	Verdict Verdict
	Mark    uint32
	Packet  []byte
}

// Packet holds the data of a network packet
type Packet struct {
	Packet          gopacket.Packet
	Mark            uint32
	verdictChannel  chan VerdictContainer
	UID             uint32
	NetworkProtocol uint8
	IfaceInIdx      int
	IfaceOutIdx     int
}

// SetVerdict emits a veredict on a packet
func (p *Packet) SetVerdict(v Verdict) {
	p.verdictChannel <- VerdictContainer{Verdict: v, Packet: nil, Mark: 0}
}

// SetVerdictAndMark emits a veredict on a packet and marks it in order to not
// analyze it again.
func (p *Packet) SetVerdictAndMark(v Verdict, mark uint32) {
	p.verdictChannel <- VerdictContainer{Verdict: v, Packet: nil, Mark: mark}
}

// SetRequeueVerdict apply a verdict on a requeued packet
func (p *Packet) SetRequeueVerdict(newQueueID uint16) {
	v := uint(NF_QUEUE)
	q := (uint(newQueueID) << 16)
	v = v | q
	p.verdictChannel <- VerdictContainer{Verdict: Verdict(v), Packet: nil, Mark: p.Mark}
}

// SetVerdictWithPacket apply a verdict, but with a new packet
func (p *Packet) SetVerdictWithPacket(v Verdict, packet []byte) {
	p.verdictChannel <- VerdictContainer{Verdict: v, Packet: packet, Mark: 0}
}

// IsIPv4 returns if the packet is IPv4
func (p *Packet) IsIPv4() bool {
	return p.NetworkProtocol == IPv4
}
