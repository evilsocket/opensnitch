package portscan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The kernel-versus-Go differential.
//
// This package contains two independent implementations of the same packet
// parsing: ebpf_prog/opensnitch-scan.c, which runs in the kernel and is the
// DEFAULT path, and parse.go, which runs behind AF_PACKET when eBPF is
// unavailable. The design says their verdicts agree by construction.
//
// Something has to check it. A security rule -- bounding the transport read by
// the length the IP header DECLARES, marking the first fragment, the
// exact-match condition on RST -- applied to the Go side alone would leave the
// kernel with the defect on the path that matters most: a `nmap -f -sS` sweep
// from the LAN would score zero on a machine where eBPF was working exactly as
// designed, because a forged RST byte in the Ethernet padding would be read as
// the TCP flags and drop the whole scan in the kernel. TestDifferentialCorpus
// cannot see any of that: it replays the corpus through ParseEthernet and
// never touches the C.
//
// So this harness runs the corpus through the REAL C. testdata/cparse compiles
// ebpf_prog/opensnitch-scan.c unmodified against a small stand-in for libbpf and
// executes it as a native program, frame by frame. Both sides then answer the
// same two questions on the same bytes -- what did you parse, and would you have
// counted it -- and they must agree on every frame in the corpus.
//
// The check that matters is not "do the tests pass" but "can this class of
// divergence still ship". With this harness, it cannot: a change applied to
// one side and not the other fails here, on real scanner traffic.

const (
	cVerdictFiltered = iota
	cVerdictForwarded
	cVerdictRateLimited
	cVerdictNoRingbuf
	cVerdictUnseen
	cVerdictSourceLimited
)

// cparseResult is one frame's verdict from the kernel program.
type cparseResult struct {
	verdict byte
	parsed  bool
	event   []byte // raw probe_event bytes, meaningful when parsed
}

// cparseRunner owns the compiled harness binary.
type cparseRunner struct {
	bin       string
	eventSize int
}

var (
	cparseOnce sync.Once
	cparseRun  *cparseRunner
	cparseErr  error
)

// findCC returns a native C compiler, or "" if there is none.
func findCC() string {
	if cc := os.Getenv("CC"); cc != "" {
		if p, err := exec.LookPath(cc); err == nil {
			return p
		}
	}
	for _, name := range []string{"cc", "gcc", "clang"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// kernelHeaderDir finds a directory holding <linux/bpf.h>.
//
// The shim replaces libbpf, not the kernel's own UAPI headers: struct __sk_buff,
// the map type constants and TC_ACT_OK come from the real linux/*.h, so that a
// change in what the program asks the kernel for is a compile error here rather
// than a silent difference of opinion between the harness and the kernel.
func kernelHeaderDir() string {
	candidates := []string{"/usr/include"}
	if extra := os.Getenv("PORTSCAN_KERNEL_HEADERS"); extra != "" {
		candidates = append([]string{extra}, candidates...)
	}
	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "linux", "bpf.h")); err == nil {
			return dir
		}
	}
	return ""
}

// buildCParse compiles the kernel program as a native binary, once per run.
func buildCParse(t *testing.T) *cparseRunner {
	t.Helper()
	cparseOnce.Do(func() {
		cc := findCC()
		if cc == "" {
			cparseErr = errors.New("no C compiler (cc, gcc or clang) on PATH")
			return
		}
		headers := kernelHeaderDir()
		if headers == "" {
			cparseErr = errors.New("no directory with <linux/bpf.h>; set PORTSCAN_KERNEL_HEADERS")
			return
		}
		dir, err := os.MkdirTemp("", "portscan-cparse")
		if err != nil {
			cparseErr = err
			return
		}
		bin := filepath.Join(dir, "cparse")
		src := filepath.Join("testdata", "cparse", "cparse.c")
		cmd := exec.Command(cc,
			"-O1", "-g", "-Wall", "-Wextra",
			"-Wno-unused-function", "-Wno-unknown-pragmas",
			"-I", filepath.Join("testdata", "cparse"),
			"-isystem", headers,
			"-o", bin, src)
		if out, err := cmd.CombinedOutput(); err != nil {
			cparseErr = fmt.Errorf("compiling the kernel program natively failed: %v\n%s", err, out)
			return
		}
		cparseRun = &cparseRunner{bin: bin}
	})
	if cparseErr != nil {
		// Deliberately not a skip when a compiler is present: a harness that
		// silently stops compiling is how the divergence it exists to catch
		// gets back in.
		// A missing compiler or missing headers is a skip on a developer's
		// machine, and a failure where PORTSCAN_REQUIRE_CPARSE=1 says the
		// differential must run: CI would otherwise go green without it.
		if strings.HasPrefix(cparseErr.Error(), "no C compiler") ||
			strings.HasPrefix(cparseErr.Error(), "no directory") {
			if os.Getenv("PORTSCAN_REQUIRE_CPARSE") == "1" {
				t.Fatalf("PORTSCAN_REQUIRE_CPARSE=1 but the kernel/Go differential cannot run: %v", cparseErr)
			}
			t.Skipf("kernel/Go differential not runnable here: %v", cparseErr)
		}
		t.Fatal(cparseErr)
	}
	return cparseRun
}

// run feeds every frame through the kernel program and returns one result each.
func (r *cparseRunner) run(t *testing.T, frames [][]byte, env ...string) []cparseResult {
	t.Helper()

	var in bytes.Buffer
	for _, f := range frames {
		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(len(f)))
		in.Write(hdr[:])
		in.Write(f)
	}

	cmd := exec.Command(r.bin)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = &in
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("cparse: %v\nstderr: %s", err, stderr.String())
	}

	raw := out.Bytes()
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 {
		t.Fatalf("cparse produced no header line; stderr: %s", stderr.String())
	}
	fields := strings.Fields(string(raw[:nl]))
	if len(fields) != 3 || fields[0] != "cparse1" {
		t.Fatalf("cparse header %q is not \"cparse1 <size> <le|be>\"", raw[:nl])
	}
	// The records are the C struct's raw memory, decoded here in this
	// machine's byte order. Under emulation (a big-endian test binary run
	// through qemu-user) the harness is still built for the host, and every
	// field would read reversed: a harness artefact, not a disagreement.
	var probe [2]byte
	binary.NativeEndian.PutUint16(probe[:], 1)
	if order := map[bool]string{true: "le", false: "be"}[probe[0] == 1]; fields[2] != order {
		t.Skipf("the harness writes %s records and this test binary is %s: it runs"+
			" under emulation, where the C half is not the same machine", fields[2], order)
	}
	size, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("cparse header size %q: %v", fields[1], err)
	}
	// The Go decoder reads the C struct with hand-written offsets. If the C
	// struct grows a field, that is where it must be noticed.
	if size != probeEventSize {
		t.Fatalf("struct probe_event is %d bytes in C but decodeProbeEvent reads %d;"+
			" the ring buffer record and its decoder have diverged", size, probeEventSize)
	}
	r.eventSize = size

	rec := 4 + size
	body := raw[nl+1:]
	if len(body) != rec*len(frames) {
		t.Fatalf("cparse returned %d bytes for %d frames, want %d", len(body), len(frames), rec*len(frames))
	}
	res := make([]cparseResult, len(frames))
	for i := range frames {
		r := body[i*rec : (i+1)*rec]
		res[i] = cparseResult{verdict: r[0], parsed: r[1] == 1, event: r[4:]}
	}
	return res
}

// goVerdict is what the Go path would do with a frame, reduced to the same two
// answers the kernel program gives: did it build a probe, and would it count it.
type goVerdict struct {
	parsed  bool
	counted bool
	probe   Probe
	reason  string
}

// kernelProbe turns the raw record the kernel program built into a Probe, by
// the same two functions the daemon uses on the ring buffer. Comparing at this
// level rather than on the raw bytes means the hand-written offsets and the
// anomaly-bit translation in fill() are under test too, not only the parser.
func kernelProbe(raw []byte) (*Probe, error) {
	var ev probeEvent
	if err := decodeProbeEvent(raw, &ev); err != nil {
		return nil, err
	}
	var p Probe
	if !ev.fill(&p) {
		return nil, errors.New("fill rejected the record")
	}
	return &p, nil
}

// evaluateGo mirrors, on the Go side, the filters tc_scan_ingress applies -- and
// only those. The harness stubs local_addrs to hit on every destination and
// leaves the exempt tries and the excluded-port map empty, so what remains in
// the kernel is: parsing refused the frame, the destination is a v4-mapped
// address in a real IPv6 packet, or the RST shortcut fired. Each has a named
// counterpart here, so a divergence points at a line rather than at a mood.
//
// The v4-mapped destination is reported as "did not parse" because the kernel
// refuses it BEFORE the point where the harness can recover the record; there
// is nothing to compare fields against, only the refusal itself.
func evaluateGo(frame []byte) goVerdict {
	var p Probe
	// The error is discarded, exactly as AFPacketSource.readLoop discards it:
	// a parse error is not a reason to drop the probe there, because throwing
	// away what WAS recovered is what made an over-long IPv6 extension chain a
	// complete evasion of that path. What gates the probe is whether a source
	// address came out of it. Mirroring the production path rather than a
	// stricter one is the whole point -- a harness that compares the kernel
	// against a Go path nobody runs proves nothing about the daemon.
	err := ParseEthernet(frame, &p)
	if !p.Src.IsValid() {
		reason := "parse recovered nothing"
		if err != nil {
			reason += ": " + err.Error()
		}
		return goVerdict{reason: reason}
	}
	isIPv6 := p.Src.Is6() && !p.Src.Is4()
	if isIPv6 && (p.Dst.Is4In6() || p.Src.Is4In6()) {
		return goVerdict{reason: "v4-mapped address in an IPv6 packet"}
	}
	v := goVerdict{parsed: true, probe: p, counted: true}

	// tc_scan_ingress: the RST shortcut, which must hold the same condition on
	// both sides. Engine.classify carries the authoritative copy.
	if p.Proto == ProtoTCP && p.TCPFlagsValid &&
		p.Anomalies&(AnomalyTruncated|AnomalyTrailer) == 0 &&
		(p.TCPFlags == TCPRst || p.TCPFlags == TCPRst|TCPAck) {
		v.counted, v.reason = false, "tcp-reset"
		return v
	}
	return v
}

// probesEqual compares the fields both sides carry, and says which differ.
func probesEqual(a, b *Probe) []string {
	var diff []string
	add := func(f string, x, y any) { diff = append(diff, fmt.Sprintf("%s: kernel=%v go=%v", f, x, y)) }
	if a.Src != b.Src {
		add("src", a.Src, b.Src)
	}
	if a.Dst != b.Dst {
		add("dst", a.Dst, b.Dst)
	}
	if a.SrcPort != b.SrcPort {
		add("sport", a.SrcPort, b.SrcPort)
	}
	if a.DstPort != b.DstPort {
		add("dport", a.DstPort, b.DstPort)
	}
	if a.Proto != b.Proto {
		add("proto", a.Proto, b.Proto)
	}
	if a.TCPFlags != b.TCPFlags {
		add("tcp_flags", fmt.Sprintf("%#02x", a.TCPFlags), fmt.Sprintf("%#02x", b.TCPFlags))
	}
	if a.TCPFlagsValid != b.TCPFlagsValid {
		add("tcp_flags_valid", a.TCPFlagsValid, b.TCPFlagsValid)
	}
	if a.Anomalies != b.Anomalies {
		add("anomalies", fmt.Sprintf("%#x", a.Anomalies), fmt.Sprintf("%#x", b.Anomalies))
	}
	if a.SrcMAC != b.SrcMAC {
		add("src_mac", a.SrcMAC, b.SrcMAC)
	}
	if a.HasMAC != b.HasMAC {
		add("has_mac", a.HasMAC, b.HasMAC)
	}
	return diff
}

// corpusFrames returns every Ethernet frame in the corpus, with a label.
func corpusFrames(t *testing.T) ([][]byte, []string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(corpusDir(), "*.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	var frames [][]byte
	var labels []string
	for _, path := range files {
		f, err := readPcap(path)
		if err != nil {
			t.Fatalf("readPcap(%s): %v", path, err)
		}
		for i, pkt := range f.Packets {
			frames = append(frames, pkt.Data)
			labels = append(labels, fmt.Sprintf("%s#%d", filepath.Base(path), i))
		}
	}
	return frames, labels
}

// TestKernelAndGoAgreeOnTheCorpus is the differential proper: every frame real
// nmap produced, through both parsers, compared field by field.
func TestKernelAndGoAgreeOnTheCorpus(t *testing.T) {
	requireCorpus(t)
	runner := buildCParse(t)
	frames, labels := corpusFrames(t)
	if len(frames) == 0 {
		t.Fatal("the corpus holds no frames")
	}

	results := runner.run(t, frames)
	var compared, divergent int
	for i, got := range results {
		want := evaluateGo(frames[i])

		if got.parsed != want.parsed {
			divergent++
			t.Errorf("%s: kernel parsed=%v, Go parsed=%v (Go: %s)",
				labels[i], got.parsed, want.parsed, want.reason)
			continue
		}
		if !got.parsed {
			continue
		}

		kp, err := kernelProbe(got.event)
		if err != nil {
			t.Errorf("%s: decoding the kernel record: %v", labels[i], err)
			continue
		}
		compared++
		if diff := probesEqual(kp, &want.probe); len(diff) > 0 {
			divergent++
			t.Errorf("%s: the two parsers read the same %d bytes differently:\n  %s\n  frame: %x",
				labels[i], len(frames[i]), strings.Join(diff, "\n  "), frames[i])
			continue
		}

		kernelCounted := got.verdict == cVerdictForwarded
		if kernelCounted != want.counted {
			divergent++
			t.Errorf("%s: kernel would count=%v, Go would count=%v (Go: %s)",
				labels[i], kernelCounted, want.counted, want.reason)
		}
	}
	t.Logf("%d frames through both parsers, %d compared field by field, %d divergent",
		len(frames), compared, divergent)
	if compared == 0 {
		t.Fatal("no frame reached the field comparison; the harness is asserting nothing")
	}
}

// TestKernelAndGoAgreeOnHostileFrames runs the differential over the frames a
// scanner would not send: truncated headers, forged trailers, extension-header
// chains, VLAN stacks. The corpus proves the two agree on real traffic; this
// proves they agree where an attacker gets to choose the bytes, which is the
// only place the disagreement was ever worth anything.
func TestKernelAndGoAgreeOnHostileFrames(t *testing.T) {
	runner := buildCParse(t)
	frames, labels := hostileFrames()

	results := runner.run(t, frames)
	for i, got := range results {
		want := evaluateGo(frames[i])
		if got.parsed != want.parsed {
			t.Errorf("%s: kernel parsed=%v, Go parsed=%v (Go: %s)\n  frame: %x",
				labels[i], got.parsed, want.parsed, want.reason, frames[i])
			continue
		}
		if !got.parsed {
			continue
		}
		kp, err := kernelProbe(got.event)
		if err != nil {
			t.Errorf("%s: decoding the kernel record: %v", labels[i], err)
			continue
		}
		if diff := probesEqual(kp, &want.probe); len(diff) > 0 {
			t.Errorf("%s: the two parsers read the same %d bytes differently:\n  %s\n  frame: %x",
				labels[i], len(frames[i]), strings.Join(diff, "\n  "), frames[i])
			continue
		}
		if kernelCounted := got.verdict == cVerdictForwarded; kernelCounted != want.counted {
			t.Errorf("%s: kernel would count=%v, Go would count=%v (Go: %s)\n  frame: %x",
				labels[i], kernelCounted, want.counted, want.reason, frames[i])
		}
	}
}

// TestCParseHarnessCanFail proves the harness is capable of failing.
//
// A differential that compares nothing passes forever. The frame below is the
// concrete attack it was built for: a fragmented TCP SYN whose IP total
// length stops before the Ethernet padding, with RST forged in that padding.
// A kernel program that did not bound its read by the declared length would
// disagree with the Go path on exactly this frame -- the kernel would read
// 0x04 as the flags and drop the scan, the Go path reads 0x02 and counts it.
// The assertions below state what each side must say; if either regresses,
// this test names the regression instead of leaving the corpus quietly
// agreeing.
func TestCParseHarnessCanFail(t *testing.T) {
	runner := buildCParse(t)

	frame := forgedTrailerFrame()
	got := runner.run(t, [][]byte{frame})[0]
	if !got.parsed {
		t.Fatal("the kernel program refused a frame it must parse")
	}
	kp, err := kernelProbe(got.event)
	if err != nil {
		t.Fatal(err)
	}
	if kp.TCPFlags != TCPSyn {
		t.Errorf("kernel read tcp flags %#02x, want %#02x (SYN): it is reading past the declared"+
			" length, into bytes the sender chose", kp.TCPFlags, TCPSyn)
	}
	if kp.Anomalies&AnomalyTrailer == 0 {
		t.Error("kernel did not mark the trailing bytes; without it the RST shortcut acts on" +
			" evidence the sender controls")
	}
	if got.verdict != cVerdictForwarded {
		t.Errorf("kernel verdict %d, want forwarded: a fragmented SYN scan must not be dropped"+
			" in the kernel by a byte in the padding", got.verdict)
	}

	// And the harness must be able to see a disagreement at all: feed the same
	// bytes to a deliberately wrong Go expectation and require a mismatch.
	want := evaluateGo(frame)
	wrong := want.probe
	wrong.TCPFlags ^= 0xff
	if diff := probesEqual(kp, &wrong); len(diff) == 0 {
		t.Fatal("probesEqual reported no difference between records that differ;" +
			" the comparison is vacuous and every test built on it proves nothing")
	}
}

// hostileFrames builds the adversarial corpus. Each entry is a shape a scanner
// or an attacker can put on the wire, chosen because it is a place where two
// hand-written parsers plausibly disagree.
func hostileFrames() ([][]byte, []string) {
	var frames [][]byte
	var labels []string
	add := func(label string, f []byte) {
		frames = append(frames, f)
		labels = append(labels, label)
	}

	add("forged-rst-in-padding", forgedTrailerFrame())

	// IPv4: total length shorter than the header it describes.
	f := ipv4Frame(0x11, 6, nil)
	binary.BigEndian.PutUint16(f[14+2:], 10)
	add("ipv4-total-length-below-ihl", f)

	// IPv4: total length longer than the frame.
	f = ipv4Frame(0x11, 6, []byte{0x00, 0x50, 0x01, 0xbb, 0x00, 0x08, 0x00, 0x00})
	binary.BigEndian.PutUint16(f[14+2:], 60000)
	add("ipv4-total-length-past-the-frame", f)

	// IPv4: a TCP header cut in half by the declared length.
	f = ipv4Frame(0x06, 6, []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0})
	binary.BigEndian.PutUint16(f[14+2:], 20+8)
	add("ipv4-tcp-header-cut-by-declared-length", f)

	// IPv4: a non-initial fragment, which has no transport header at all.
	f = ipv4Frame(0x06, 6, []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0})
	binary.BigEndian.PutUint16(f[14+6:], 0x0001) // fragment offset 1
	add("ipv4-non-initial-fragment", f)

	// IPv4: IHL claiming options that are not there.
	f = ipv4Frame(0x06, 6, []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0})
	f[14] = 0x4f // IHL 15 => 60 bytes of header
	add("ipv4-ihl-past-the-payload", f)

	// IPv6: payload length zero with a Hop-by-Hop header, the jumbogram
	// convention the kernel treats as "trust the frame" and nothing else does.
	add("ipv6-zero-payload-len-hopopts", ipv6ZeroPayloadHopByHop())

	// IPv6: payload length zero WITHOUT Hop-by-Hop, where the exception must not
	// apply and the packet carries no transport header.
	f = ipv6Frame(0x06, []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0})
	binary.BigEndian.PutUint16(f[14+4:], 0)
	add("ipv6-zero-payload-len-no-hopopts", f)

	// IPv6: payload length shorter than the transport header present.
	f = ipv6Frame(0x06, []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0})
	binary.BigEndian.PutUint16(f[14+4:], 8)
	add("ipv6-payload-len-cuts-tcp", f)

	// Extension headers that OVERRUN the declared payload length.
	//
	// This shape was missing, and it is the one that mattered: the walk is
	// bounded on both sides by the same arithmetic but not by the same bytes.
	// parseIPv6 truncates to the declared length and then walks, so an
	// overrunning header stops the walk on itself; the kernel walked with
	// bpf_skb_load_bytes, bounded by the frame, stepped over the header and
	// reported whatever Next Header byte lay past the declared end. Five frames
	// out of five disagreed, with the kernel claiming proto=6 for packets
	// carrying no TCP header at all.
	tcpSyn := []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, TCPSyn, 0, 0, 0, 0, 0, 0}

	// Hop-by-Hop declaring 16 bytes where Payload Length allows 8, then a
	// trailer holding a complete TCP header.
	hop := make([]byte, 8)
	hop[0] = 0x06
	hop[1] = 1 // (1+1)*8 = 16 bytes declared, only 8 present within the payload
	f = ipv6Frame(0, append(append([]byte(nil), hop...), tcpSyn...))
	binary.BigEndian.PutUint16(f[14+4:], 8)
	add("ipv6-ext-overruns-declared-length", f)

	// A Fragment header cut after two bytes: the offset field is outside the
	// declared payload, so it cannot be read.
	f = ipv6Frame(44, append([]byte{0x06, 0x00}, tcpSyn...))
	binary.BigEndian.PutUint16(f[14+4:], 2)
	add("ipv6-fragment-header-cut-at-2", f)

	// Three bytes: still one short of the offset field. A kernel program that
	// ignored the failed read would walk on regardless.
	f = ipv6Frame(44, append([]byte{0x06, 0x00, 0x01}, tcpSyn...))
	binary.BigEndian.PutUint16(f[14+4:], 3)
	add("ipv6-fragment-header-cut-at-3", f)

	// Destination Options overrunning, with a full SYN in the trailer.
	dst := make([]byte, 8)
	dst[0] = 0x06
	dst[1] = 2 // (2+1)*8 = 24 declared
	f = ipv6Frame(60, append(append([]byte(nil), dst...), tcpSyn...))
	binary.BigEndian.PutUint16(f[14+4:], 8)
	add("ipv6-dstopts-overruns-with-syn-trailer", f)

	// An Authentication Header cut short. Its length convention is (n+2)*4, so
	// the arithmetic differs from every other header's.
	ah := make([]byte, 4)
	ah[0] = 0x06
	ah[1] = 4 // (4+2)*4 = 24 declared
	f = ipv6Frame(51, append(append([]byte(nil), ah...), tcpSyn...))
	binary.BigEndian.PutUint16(f[14+4:], 4)
	add("ipv6-auth-header-cut", f)

	// IPv6: an extension chain longer than either side will walk.
	add("ipv6-ext-chain-overlong", ipv6LongExtChain(12))
	// IPv6: a chain just at the header-count bound.
	add("ipv6-ext-chain-at-bound", ipv6LongExtChain(maxExtHeaders))
	// IPv6: one Destination Options header declaring more bytes than the frame
	// holds -- the byte budget, not the header count, is what bounds this.
	add("ipv6-ext-chain-overlong-bytes", ipv6FatExtHeader())

	// VLAN stacks: at the bound, and one past it.
	add("vlan-single", vlanFrame(1))
	add("vlan-double", vlanFrame(2))
	add("vlan-triple", vlanFrame(3))

	// Truncations of a plain SYN, one byte at a time: the classic place a parser
	// reads one byte past what it verified.
	base := ipv4Frame(0x06, 6, []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0})
	for n := 0; n <= len(base); n++ {
		add(fmt.Sprintf("truncated-to-%d", n), append([]byte(nil), base[:n]...))
	}

	// A genuine IPv6 packet addressed to a v4-mapped destination.
	f = ipv6Frame(0x06, []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0})
	copy(f[14+24:14+40], netip.MustParseAddr("::ffff:10.77.0.1").AsSlice())
	add("ipv6-v4mapped-destination", f)

	// A genuine IPv6 packet FROM a v4-mapped source. RFC 4291 forbids it on the
	// wire and Linux drops it in ip6_rcv, but TC ingress runs first -- so the
	// two paths get to see a packet the host never processes, and they had
	// better agree on whose address it is.
	f = ipv6Frame(0x06, []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0})
	copy(f[14+8:14+24], netip.MustParseAddr("::ffff:10.77.0.9").AsSlice())
	add("ipv6-v4mapped-source", f)

	// Every TCP flag combination, on an otherwise ordinary frame: this is where
	// the RST shortcut lives and where the two sides must agree exactly.
	for fl := 0; fl < 256; fl++ {
		body := []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, byte(fl), 0, 0, 0, 0, 0, 0}
		add(fmt.Sprintf("tcp-flags-%#02x", fl), ipv4Frame(0x06, 6, body))
	}

	// Branches no frame above reached, found by mutation: either parser could
	// lose these guards and the differential stayed green.
	syn := []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, TCPSyn, 0x72, 0x10, 0, 0, 0, 0}

	// IPv6 non-initial fragment: offset 1, next header TCP, bytes that look
	// like a SYN. They are fragment payload, not a header.
	frag := []byte{0x06, 0x00, 0x00, 0x08, 0, 0, 0, 1} // offset 1, in 8-byte units <<3
	add("ipv6-non-initial-fragment", ipv6Frame(44, append(frag, syn...)))

	// IPv4 fragment offset with bit 12 set (>= 32768 bytes): a mask that drops
	// that bit reads it as an initial fragment.
	f = ipv4Frame(0x06, 0, append([]byte(nil), syn...))
	binary.BigEndian.PutUint16(f[14+6:], 0x1000)
	add("ipv4-fragment-offset-bit-12", f)

	// Destination Options chains either side of both bounds: eight headers is
	// the most the walk takes, nine is one too many; 1024 bytes is the most it
	// walks, 1088 is past it.
	chain := func(n, extLen int) []byte {
		var b []byte
		for i := 0; i < n; i++ {
			h := make([]byte, (extLen+1)*8)
			h[0] = 60 // next: another Destination Options header
			if i == n-1 {
				h[0] = 0x06
			}
			h[1] = byte(extLen)
			b = append(b, h...)
		}
		return append(b, syn...)
	}
	add("ipv6-8-extension-headers", ipv6Frame(60, chain(8, 0)))
	add("ipv6-9-extension-headers", ipv6Frame(60, chain(9, 0)))
	add("ipv6-extension-chain-1024-bytes", ipv6Frame(60, chain(8, 15)))
	add("ipv6-extension-chain-1088-bytes", ipv6Frame(60, chain(8, 16)))
	// One header, 2048 bytes long, starting well under the bound.
	add("ipv6-one-2048-byte-extension", ipv6Frame(60, chain(1, 255)))

	return frames, labels
}

// --- frame builders -------------------------------------------------------
//
// Deliberately hand-rolled rather than borrowed from parse.go's own helpers: a
// builder that shares code with one of the two parsers under comparison can only
// produce frames that parser already agrees with.

const (
	cpSrcMAC = "\xaa\xbb\xcc\xdd\xee\xff"
	cpDstMAC = "\x02\x00\x00\x00\x00\x01"
)

func ethHeader(ethertype uint16) []byte {
	h := make([]byte, 14)
	copy(h[0:6], cpDstMAC)
	copy(h[6:12], cpSrcMAC)
	binary.BigEndian.PutUint16(h[12:], ethertype)
	return h
}

// ipv4Frame builds an Ethernet+IPv4 frame with the given protocol and payload.
// totalLenExtra shifts the declared total length away from the truth.
func ipv4Frame(proto byte, totalLenExtra int, payload []byte) []byte {
	_ = totalLenExtra
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(payload)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], netip.MustParseAddr("10.77.0.9").AsSlice())
	copy(ip[16:20], netip.MustParseAddr("10.77.0.1").AsSlice())
	f := append(ethHeader(0x0800), ip...)
	return append(f, payload...)
}

func ipv6Frame(nexthdr byte, payload []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(payload)))
	ip[6] = nexthdr
	ip[7] = 64
	copy(ip[8:24], netip.MustParseAddr("fd00:77::9").AsSlice())
	copy(ip[24:40], netip.MustParseAddr("fd00:77::1").AsSlice())
	f := append(ethHeader(0x86dd), ip...)
	return append(f, payload...)
}

// forgedTrailerFrame is that attack, verbatim: a fragmented
// TCP SYN whose IP total length stops at the end of the TCP header, followed by
// bytes the sender chose, positioned so a parser that trusts the frame length
// reads 0x04 (RST) as the flags.
func forgedTrailerFrame() []byte {
	tcp := []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, TCPSyn, 0, 0, 0, 0, 0, 0}
	f := ipv4Frame(0x06, 0, tcp)
	binary.BigEndian.PutUint16(f[14+6:], 0x2000) // More Fragments, offset 0
	// The declared total length already stops after the TCP header; append the
	// forged tail so a parser bounding on the frame reads it instead.
	tail := make([]byte, 20)
	tail[13] = TCPRst
	return append(f, tail...)
}

func ipv6ZeroPayloadHopByHop() []byte {
	tcp := []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, TCPSyn, 0, 0, 0, 0, 0, 0}
	hop := make([]byte, 8)
	hop[0] = 0x06 // next header: TCP
	hop[1] = 0    // (0+1)*8 = 8 bytes
	body := append(hop, tcp...)
	f := ipv6Frame(0, body)
	binary.BigEndian.PutUint16(f[14+4:], 0)
	return f
}

func ipv6LongExtChain(n int) []byte {
	tcp := []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, TCPSyn, 0, 0, 0, 0, 0, 0}
	body := []byte(nil)
	for i := 0; i < n; i++ {
		h := make([]byte, 8)
		if i == n-1 {
			h[0] = 0x06
		} else {
			h[0] = 60 // Destination Options
		}
		h[1] = 0
		body = append(body, h...)
	}
	return ipv6Frame(60, append(body, tcp...))
}

// ipv6FatExtHeader declares a single Destination Options header of 2048 bytes,
// the shape that made a byte budget necessary alongside the header count.
func ipv6FatExtHeader() []byte {
	h := make([]byte, 2048)
	h[0] = 0x06
	h[1] = 255 // (255+1)*8 = 2048
	tcp := []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, TCPSyn, 0, 0, 0, 0, 0, 0}
	return ipv6Frame(60, append(h, tcp...))
}

func vlanFrame(depth int) []byte {
	f := ethHeader(0x8100)
	for i := 0; i < depth; i++ {
		tag := []byte{0x00, 0x64, 0x00, 0x00}
		if i == depth-1 {
			binary.BigEndian.PutUint16(tag[2:], 0x0800)
		} else {
			binary.BigEndian.PutUint16(tag[2:], 0x8100)
		}
		f = append(f, tag...)
	}
	inner := ipv4Frame(0x06, 0, []byte{0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, TCPSyn, 0, 0, 0, 0, 0, 0})
	return append(f, inner[14:]...)
}

// TestKernelStartupGraceSparesOnlyAcknowledgingTCP runs the kernel program with
// its clock inside the start-up grace. Only TCP carrying ACK may be dropped:
// a program that dropped everything would mean that on the eBPF path -- the
// preferred one -- a full SYN sweep in the first minute after every boot never
// reached the engine at all, whatever the engine's own grace said.
func TestKernelStartupGraceSparesOnlyAcknowledgingTCP(t *testing.T) {
	runner := buildCParse(t)
	tcp := func(flags byte) []byte {
		return ipv4Frame(0x06, 0, []byte{0x9c, 0x40, 0x00, 0x16, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0x72, 0x10, 0, 0, 0, 0})
	}
	udp := ipv4Frame(0x11, 0, []byte{0x9c, 0x40, 0x00, 0x35, 0, 8, 0, 0})
	cases := []struct {
		name  string
		frame []byte
		spare bool
	}{
		{"SYN", tcp(TCPSyn), false},
		{"FIN", tcp(TCPFin), false},
		{"NULL", tcp(0), false},
		{"UDP", udp, false},
		{"ACK", tcp(TCPAck), true},
		{"FIN|ACK", tcp(TCPFin | TCPAck), true},
		{"SYN|ACK", tcp(TCPSyn | TCPAck), true},
	}
	frames := make([][]byte, len(cases))
	for i, c := range cases {
		frames[i] = c.frame
	}
	// shim_now_ns is one second; a deadline an hour later is inside the grace.
	inside := runner.run(t, frames, fmt.Sprintf("CPARSE_GRACE_UNTIL_NS=%d", uint64(time.Hour)))
	after := runner.run(t, frames, "CPARSE_GRACE_UNTIL_NS=1")
	for i, c := range cases {
		if after[i].verdict != cVerdictForwarded {
			t.Fatalf("%s after the grace: verdict %d, want forwarded; the test does not"+
				" exercise its case", c.name, after[i].verdict)
		}
		spared := inside[i].verdict != cVerdictForwarded
		if spared != c.spare {
			t.Errorf("%s inside the start-up grace: dropped=%v, want %v", c.name, spared, c.spare)
		}
	}
}

// TestKernelBudgetsAreCountedApart: the program counts a probe refused by the
// source's own budget apart from one refused by the aggregate budget, since
// only the second is degraded detection for everyone (see
// Monitor.checkSourceDegradation). Counted together, every large download
// would raise that warning; without this test, only the qemu harness would
// check it.
func TestKernelBudgetsAreCountedApart(t *testing.T) {
	runner := buildCParse(t)
	syn := [][]byte{ipv4Frame(0x06, 0, []byte{0x9c, 0x40, 0x00, 0x16, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x72, 0x10, 0, 0, 0, 0})}
	for _, c := range []struct {
		spent string
		want  byte
	}{
		{"", cVerdictForwarded},
		{"source", cVerdictSourceLimited},
		{"total", cVerdictRateLimited},
		{"total-known", cVerdictRateLimited},
	} {
		if got := runner.run(t, syn, "CPARSE_BUDGET_SPENT="+c.spent)[0].verdict; got != c.want {
			t.Errorf("with the %q budget spent: verdict %d, want %d", c.spent, got, c.want)
		}
	}
}

// TestKernelReadsALinklessFrameAsIP: on an interface with no link header (tun,
// wg, ppp, sit) the frame begins at the IP header, and its bytes 12-13 are part
// of the source address. Read as an Ethernet type first, a source in
// 8.0.0.0/16 or 134.221.0.0/16, or an IPv6 one whose third group is 0800 or
// 86dd, would pass for IP inside Ethernet and be parsed at the wrong offset.
// Both paths must see every such source as the Go parser does.
func TestKernelReadsALinklessFrameAsIP(t *testing.T) {
	runner := buildCParse(t)
	syn4 := func(src netip.Addr) []byte {
		b := make([]byte, 44)
		b[0], b[8], b[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(b[2:], 44)
		s, d := src.As4(), netip.MustParseAddr("10.0.0.5").As4()
		copy(b[12:16], s[:])
		copy(b[16:20], d[:])
		tcp := b[20:]
		binary.BigEndian.PutUint16(tcp[0:], 40000)
		binary.BigEndian.PutUint16(tcp[2:], 22)
		tcp[12], tcp[13] = 6<<4, TCPSyn
		tcp[20], tcp[21] = 2, 4 // MSS
		binary.BigEndian.PutUint16(tcp[22:], 1460)
		return b
	}
	syn6 := func(src netip.Addr) []byte {
		b := make([]byte, 64)
		b[0], b[6], b[7] = 0x60, 6, 64
		binary.BigEndian.PutUint16(b[4:], 24)
		s, d := src.As16(), netip.MustParseAddr("2001:db8:1::5").As16()
		copy(b[8:24], s[:])
		copy(b[24:40], d[:])
		tcp := b[40:]
		binary.BigEndian.PutUint16(tcp[0:], 40000)
		binary.BigEndian.PutUint16(tcp[2:], 22)
		tcp[12], tcp[13] = 6<<4, TCPSyn
		tcp[20], tcp[21] = 2, 4
		binary.BigEndian.PutUint16(tcp[22:], 1440)
		return b
	}
	srcs := []string{"9.0.1.2", "8.0.1.2", "8.0.69.2", "134.221.1.2", "8.0.134.221",
		"2001:db8:900::66", "2001:db8:800::66", "2001:db8:86dd::66", "2001:db8:8100::66"}
	frames := make([][]byte, len(srcs))
	for i, s := range srcs {
		if a := netip.MustParseAddr(s); a.Is4() {
			frames[i] = syn4(a)
		} else {
			frames[i] = syn6(a)
		}
	}
	got := runner.run(t, frames, "CPARSE_L2LESS=1")
	for i, s := range srcs {
		var want Probe
		if err := ParseIP(frames[i], &want); err != nil {
			t.Fatalf("%s: the Go parser refused the frame: %v", s, err)
		}
		if got[i].verdict != cVerdictForwarded {
			t.Errorf("%s: the kernel program did not forward it (verdict %d)", s, got[i].verdict)
			continue
		}
		kp, err := kernelProbe(got[i].event)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if kp.Src != want.Src || kp.Dst != want.Dst || kp.DstPort != want.DstPort || kp.TCPFlags != want.TCPFlags {
			t.Errorf("%s: kernel read %v -> %v:%d flags %#x, Go %v -> %v:%d flags %#x", s,
				kp.Src, kp.Dst, kp.DstPort, kp.TCPFlags, want.Src, want.Dst, want.DstPort, want.TCPFlags)
		}
	}
}
