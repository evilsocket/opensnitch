package netfilter

import "C"

import (
	"github.com/google/gopacket"
)

type Verdict C.uint

type VerdictContainer struct {
	Verdict Verdict
	Mark    uint32
	Packet  []byte
}

type NFPacket struct {
	Packet         gopacket.Packet
	Mark           uint32
	verdictChannel chan VerdictContainer
}

func (p *NFPacket) SetVerdict(v Verdict) {
	p.verdictChannel <- VerdictContainer{Verdict: v, Packet: nil, Mark: 0}
}

func (p *NFPacket) SetVerdictAndMark(v Verdict, mark uint32) {
	p.verdictChannel <- VerdictContainer{Verdict: v, Packet: nil, Mark: mark}
}

func (p *NFPacket) SetRequeueVerdict(newQueueId uint16) {
	v := uint(NF_QUEUE)
	q := (uint(newQueueId) << 16)
	v = v | q
	p.verdictChannel <- VerdictContainer{Verdict: Verdict(v), Packet: nil, Mark: 0}
}

func (p *NFPacket) SetVerdictWithPacket(v Verdict, packet []byte) {
	p.verdictChannel <- VerdictContainer{Verdict: v, Packet: packet, Mark: 0}
}
