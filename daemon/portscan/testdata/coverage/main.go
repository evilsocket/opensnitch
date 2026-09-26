// Command coverage generates the "Port Scan Detection: Coverage" wiki page.
//
// The output lives in the project wiki rather than in the repository: OpenSnitch
// documents itself at github.com/evilsocket/opensnitch/wiki, so a docs/ directory
// here would be a second place for the same thing to go stale.
//
// It replays every capture in the corpus through the real detection engine and
// renders the taxonomy in daemon/portscan/coverage.go alongside what was
// actually observed. The report is therefore a record of what the code does,
// not of what it is meant to do -- which is the only kind of coverage claim
// worth publishing.
//
// Usage:
//
//	go run ./portscan/testdata/coverage -corpus portscan/testdata/pcap -o Port-Scan-Detection-Coverage.md
//	go run ./portscan/testdata/coverage -check      # fail if the file is stale
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/evilsocket/opensnitch/daemon/portscan"
)

// The corpus is generated against these addresses; see
// portscan/testdata/generate_corpus.sh.
var (
	victim4 = netip.MustParseAddr("10.77.0.1")
	victim6 = netip.MustParseAddr("fd00:77::1")
)

// corpusHost mirrors the one the differential test uses: the victim owns its
// two addresses, nothing listens, and no connection is known. That is the
// hostile-but-plausible view a scan arrives into.
type corpusHost struct{}

func (corpusHost) IsLocalUnicast(a netip.Addr) bool { return a == victim4 || a == victim6 }
func (corpusHost) IsListening(uint8, uint16) bool   { return false }
func (corpusHost) HasConnection(*portscan.Probe) bool {
	return false
}
func (corpusHost) IsOnLink(netip.Addr) bool { return true }
func (corpusHost) IsExempt(netip.Addr) bool { return false }

func main() {
	corpus := flag.String("corpus", "portscan/testdata/pcap", "directory holding the capture corpus")
	out := flag.String("o", "Port-Scan-Detection-Coverage.md", "file to write")
	check := flag.Bool("check", false, "do not write; fail if the file on disk differs")
	flag.Parse()

	cfg := portscan.DefaultConfig()
	// Enabled, explicitly.
	//
	// DefaultConfig ships with Enabled false, so that installing OpenSnitch
	// does not silently start watching traffic. Engine.Process returns on its
	// first line when it is false, so this generator replayed the whole corpus
	// against a detector that was switched off and published a coverage page
	// saying every technique was "not reported" -- a page whose entire purpose
	// is to state, honestly, what this feature detects.
	//
	// The CI guard did not catch it because it grepped for a marker that lives
	// in the hand-written column, not in the measured one.
	cfg.Enabled = true
	cfg.StartupGrace = 0

	results := map[string]portscan.CoverageResult{}
	missing := []string{}
	for _, name := range portscan.CorpusNames() {
		path := filepath.Join(*corpus, name+".pcap")
		r, err := replay(path, cfg)
		if err != nil {
			missing = append(missing, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		results[name] = r
	}

	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d capture(s) could not be replayed:\n", len(missing))
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "  %s\n", m)
		}
		fmt.Fprintln(os.Stderr, "run portscan/testdata/generate_corpus.sh to produce them")
	}

	var buf bytes.Buffer
	if err := portscan.RenderCoverage(&buf, cfg, results); err != nil {
		fmt.Fprintf(os.Stderr, "rendering: %v\n", err)
		os.Exit(1)
	}

	if *check {
		have, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s: %v\n", *out, err)
			os.Exit(1)
		}
		if !bytes.Equal(have, buf.Bytes()) {
			fmt.Fprintf(os.Stderr, "%s is stale; regenerate it\n", *out)
			os.Exit(1)
		}
		fmt.Printf("%s is up to date\n", *out)
		return
	}

	if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d techniques, %d replayed captures)\n",
		*out, len(portscan.Techniques), len(results))
}

// replay feeds one capture through a fresh engine.
func replay(path string, cfg portscan.Config) (portscan.CoverageResult, error) {
	frames, err := readPcap(path)
	if err != nil {
		return portscan.CoverageResult{}, err
	}
	engine, err := portscan.NewEngine(cfg, corpusHost{}, 0)
	if err != nil {
		return portscan.CoverageResult{}, err
	}

	res := portscan.CoverageResult{Packets: len(frames)}
	var first *portscan.ScanEvent
	for _, f := range frames {
		var p portscan.Probe
		p.TimeNs = f.timeNs
		if err := portscan.ParseEthernet(f.data, &p); err != nil &&
			err != portscan.ErrNoTransport {
			continue
		}
		if !p.Src.IsValid() {
			continue
		}
		res.Probes++
		if ev := engine.Process(&p); ev != nil && first == nil {
			first = ev
		}
	}

	if first != nil {
		res.Detected = true
		res.Method = first.Method
		res.Detail = first.MethodDetail
		res.Ports = first.DistinctPorts
		res.MinPort, res.MaxPort = first.MinPort, first.MaxPort
		res.Score = first.Score
		res.Flags = first.FlagsSummary
		res.Protocol = first.IsProtocolScan
	}
	return res, nil
}

type frame struct {
	timeNs uint64
	data   []byte
}

// readPcap reads a libpcap savefile, returning frames with timestamps relative
// to the first packet.
func readPcap(path string) ([]frame, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if len(raw) < 24 {
		return nil, fmt.Errorf("shorter than a pcap header")
	}
	var bo binary.ByteOrder
	nanos := false
	switch binary.LittleEndian.Uint32(raw[0:4]) {
	case 0xa1b2c3d4:
		bo = binary.LittleEndian
	case 0xa1b23c4d:
		bo, nanos = binary.LittleEndian, true
	case 0xd4c3b2a1:
		bo = binary.BigEndian
	case 0x4d3cb2a1:
		bo, nanos = binary.BigEndian, true
	default:
		return nil, fmt.Errorf("unrecognised pcap magic")
	}
	if lt := bo.Uint32(raw[20:24]); lt != 1 {
		return nil, fmt.Errorf("link type %d is not Ethernet", lt)
	}

	var (
		out   []frame
		base  uint64
		first = true
		off   = 24
	)
	for off+16 <= len(raw) {
		sec := uint64(bo.Uint32(raw[off : off+4]))
		frac := uint64(bo.Uint32(raw[off+4 : off+8]))
		n := int(bo.Uint32(raw[off+8 : off+12]))
		off += 16
		if n < 0 || off+n > len(raw) {
			break
		}
		ts := sec * 1e9
		if nanos {
			ts += frac
		} else {
			ts += frac * 1000
		}
		if first {
			base, first = ts, false
		}
		out = append(out, frame{timeNs: ts - base, data: raw[off : off+n]})
		off += n
	}
	return out, nil
}
