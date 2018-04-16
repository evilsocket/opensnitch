package tls

import (
	// "net"
	// "sync"
	"encoding/binary"
	"encoding/hex"
	"regexp"

	"github.com/evilsocket/opensnitch/daemon/log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	// responses = make(map[string]string, 0)
	// lock = sync.Mutex{}

	tlsCertInfoRe = regexp.MustCompile("\x16.{2}.{2}\x0b.{3}.{3}")
)

func TrackCertificates(packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if ok == false || tcp == nil {
		return false
	}

	if tcp.SrcPort != 443 {
		return false
	}

	data := tcp.Payload
	dataSize := len(data)
	dataLeft := dataSize
	if dataSize < 5 {
		return false
	}

	recordType := data[0]
	if recordType != 0x16 { // handshake
		return false
	}

	// tlsVersion := data[1:3]
	recordSize := int(binary.BigEndian.Uint16(data[3:5]))
	if recordSize > dataLeft {
		return false
	}

	data = data[recordSize:]
	m := tlsCertInfoRe.FindSubmatchIndex(data)
	if m == nil || len(m) < 1 {
		return false
	}

	log.Info("OK")

	certsOffset := m[0]
	certs := data[certsOffset:]
	if len(certs) < 5 {
		return false
	}
	certs = certs[5:]

	certsLen := uint32(certs[4])<<16 | uint32(certs[5])<<8 | uint32(certs[6])

	log.Info("certsLength:%d tot:%d", certsLen, len(certs))
	log.Info("%s", hex.Dump(certs))
	/*

		log.Info("HEADER: %s", hex.Dump(certs[0:8]))
		log.Info("type = 0x%x", certs[0])
		log.Info("tlen = %d", len(certs))
		log.Info("len  = %s", hex.Dump(certs[1:4]))
		log.Info("clen = %s", hex.Dump(certs[4:7]))

		certsLength := binary.BigEndian.Uint32(append([]byte{0}, certs[4:7]...))
	*/
	return true
}
