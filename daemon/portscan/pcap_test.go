package portscan

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Minimal libpcap savefile reader, used only by the differential harness.
//
// Reading the corpus with a hand-written parser rather than a pcap library
// keeps the test suite free of cgo and of any dependency the daemon does not
// already carry. The format is fully specified by its four-byte magic and two
// fixed-size headers.
type pcapPacket struct {
	// TimeNs is the capture timestamp converted to nanoseconds since the
	// epoch. The engine only ever compares timestamps to each other, so any
	// consistent origin works.
	TimeNs uint64
	Data   []byte
}

const (
	pcapMagicMicroLE = 0xa1b2c3d4
	pcapMagicMicroBE = 0xd4c3b2a1
	pcapMagicNanoLE  = 0xa1b23c4d
	pcapMagicNanoBE  = 0x4d3cb2a1

	linkTypeEthernet = 1
	linkTypeRaw      = 101
	linkTypeLinuxSLL = 113
)

type pcapFile struct {
	LinkType uint32
	Packets  []pcapPacket
}

func readPcap(path string) (*pcapFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < 24 {
		return nil, fmt.Errorf("%s: file shorter than a pcap header", path)
	}

	var bo binary.ByteOrder
	nano := false
	switch m := binary.LittleEndian.Uint32(raw[0:4]); m {
	case pcapMagicMicroLE:
		bo = binary.LittleEndian
	case pcapMagicNanoLE:
		bo, nano = binary.LittleEndian, true
	case pcapMagicMicroBE:
		bo = binary.BigEndian
	case pcapMagicNanoBE:
		bo, nano = binary.BigEndian, true
	default:
		return nil, fmt.Errorf("%s: unrecognised pcap magic %#08x", path, m)
	}

	f := &pcapFile{LinkType: bo.Uint32(raw[20:24])}
	off := 24
	for off+16 <= len(raw) {
		tsSec := uint64(bo.Uint32(raw[off : off+4]))
		tsFrac := uint64(bo.Uint32(raw[off+4 : off+8]))
		inclLen := int(bo.Uint32(raw[off+8 : off+12]))
		off += 16
		if inclLen < 0 || off+inclLen > len(raw) {
			return nil, fmt.Errorf("%s: truncated packet record at offset %d", path, off)
		}
		ns := tsSec*1e9 + tsFrac*1000
		if nano {
			ns = tsSec*1e9 + tsFrac
		}
		f.Packets = append(f.Packets, pcapPacket{TimeNs: ns, Data: raw[off : off+inclLen]})
		off += inclLen
	}
	return f, nil
}

// probesFrom converts a capture into Probes using the production parser.
//
// timeBase and timeScale let a test replay the same real packets at a
// different tempo, which is how the slow-scan behaviour is exercised without
// spending ten minutes capturing an nmap -T1 run.
func (f *pcapFile) probesFrom(timeBase uint64, timeScale float64) ([]*Probe, error) {
	if f.LinkType != linkTypeEthernet {
		return nil, fmt.Errorf("link type %d is not Ethernet; the corpus must be captured on a real L2 interface so the source MAC is present", f.LinkType)
	}
	if len(f.Packets) == 0 {
		return nil, nil
	}
	origin := f.Packets[0].TimeNs
	out := make([]*Probe, 0, len(f.Packets))
	for _, pk := range f.Packets {
		p := &Probe{}
		err := ParseEthernet(pk.Data, p)
		// ErrNoTransport still yields a usable probe: the addresses and the
		// protocol number are set, and those alone reveal an IP protocol scan.
		if err != nil && err != ErrNoTransport {
			continue
		}
		if !p.Src.IsValid() {
			continue
		}
		delta := float64(pk.TimeNs-origin) * timeScale
		p.TimeNs = timeBase + uint64(delta)
		out = append(out, p)
	}
	return out, nil
}
