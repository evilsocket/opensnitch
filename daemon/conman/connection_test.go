package conman

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/evilsocket/opensnitch/daemon/netfilter"
)

// Adding new packets:
// wireshark -> right click -> Copy as HexDump -> create []byte{}

func NewTCPPacket() gopacket.Packet {
	// 47676:192.168.1.100 -> 1.1.1.1:23
	testTCPPacket := []byte{0x4c, 0x6e, 0x6e, 0xd5, 0x79, 0xbf, 0x00, 0x28, 0x9d, 0x43, 0x7f, 0xd7, 0x08, 0x00, 0x45, 0x10,
		0x00, 0x3c, 0x1d, 0x07, 0x40, 0x00, 0x40, 0x06, 0x59, 0x8e, 0xc0, 0xa8, 0x01, 0x6d, 0x01, 0x01,
		0x01, 0x01, 0xba, 0x3c, 0x00, 0x17, 0x47, 0x7e, 0xf3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
		0xfa, 0xf0, 0x4c, 0x27, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x91, 0xfb,
		0xb5, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x0a}
	return gopacket.NewPacket(testTCPPacket, layers.LinkTypeEthernet, gopacket.Default)
}

func NewUDPPacket() gopacket.Packet {
	// 29517:192.168.1.109 -> 1.0.0.1:53
	testUDPPacketDNS := []byte{
		0x4c, 0x6e, 0x6e, 0xd5, 0x79, 0xbf, 0x00, 0x28, 0x9d, 0x43, 0x7f, 0xd7, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x40, 0x54, 0x1a, 0x40, 0x00, 0x3f, 0x11, 0x24, 0x7d, 0xc0, 0xa8, 0x01, 0x6d, 0x01, 0x00,
		0x00, 0x01, 0x73, 0x4d, 0x00, 0x35, 0x00, 0x2c, 0xf1, 0x17, 0x05, 0x51, 0x00, 0x20, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x70, 0x69, 0x04, 0x68, 0x6f, 0x6c, 0x65, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
	}

	return gopacket.NewPacket(testUDPPacketDNS, layers.LinkTypeEthernet, gopacket.Default)
}

func EstablishConnection(proto, dst string) (net.Conn, error) {
	c, err := net.Dial(proto, dst)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return c, nil
}

func ListenOnPort(proto, port string) (net.Listener, error) {
	l, err := net.Listen(proto, port)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return l, nil
}

func NewPacket(pkt gopacket.Packet) *netfilter.Packet {
	return &netfilter.Packet{
		Packet:          pkt,
		UID:             666,
		NetworkProtocol: netfilter.IPv4,
	}
}

func NewDummyConnection(src, dst net.IP) *Connection {
	return &Connection{
		SrcIP: src,
		DstIP: dst,
	}
}

// Test TCP parseDirection()
func TestParseTCPDirection(t *testing.T) {
	srcIP := net.IP{192, 168, 1, 100}
	dstIP := net.IP{1, 1, 1, 1}
	c := NewDummyConnection(srcIP, dstIP)
	// 47676:192.168.1.100 -> 1.1.1.1:23
	pkt := NewPacket(NewTCPPacket())
	c.Pkt = pkt

	// parseDirection extracts the src and dst port from a network packet.
	if c.parseDirection("") == false {
		t.Error("parseDirection() should not be false")
		t.Fail()
	}
	if c.SrcPort != 47676 {
		t.Error("parseDirection() SrcPort mismatch:", c)
		t.Fail()
	}
	if c.DstPort != 23 {
		t.Error("parseDirection() DstPort mismatch:", c)
		t.Fail()
	}
	if c.Protocol != "tcp" {
		t.Error("parseDirection() Protocol mismatch:", c)
		t.Fail()
	}
}

// Test UDP parseDirection()
func TestParseUDPDirection(t *testing.T) {
	srcIP := net.IP{192, 168, 1, 100}
	dstIP := net.IP{1, 0, 0, 1}
	c := NewDummyConnection(srcIP, dstIP)
	// 29517:192.168.1.109 -> 1.0.0.1:53
	pkt := NewPacket(NewUDPPacket())
	c.Pkt = pkt

	// parseDirection extracts the src and dst port from a network packet.
	if c.parseDirection("") == false {
		t.Error("parseDirection() should not be false")
		t.Fail()
	}
	if c.SrcPort != 29517 {
		t.Error("parseDirection() SrcPort mismatch:", c)
		t.Fail()
	}
	if c.DstPort != 53 {
		t.Error("parseDirection() DstPort mismatch:", c)
		t.Fail()
	}
	if c.Protocol != "udp" {
		t.Error("parseDirection() Protocol mismatch:", c)
		t.Fail()
	}
}
