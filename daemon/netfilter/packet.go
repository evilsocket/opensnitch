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

func (p *Packet) SetRequeueVerdict(newQueueId uint16) {
	v := uint(NF_QUEUE)
	q := (uint(newQueueId) << 16)
	v = v | q
	p.verdictChannel <- VerdictContainer{Verdict: Verdict(v), Packet: nil, Mark: 0}
}

func (p *Packet) SetVerdictWithPacket(v Verdict, packet []byte) {
	p.verdictChannel <- VerdictContainer{Verdict: v, Packet: packet, Mark: 0}
}

// IsIPv4 returns if the packet is IPv4
func (p *Packet) IsIPv4() bool {
	return p.NetworkProtocol == IPv4
}
