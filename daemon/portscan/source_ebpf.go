//go:build linux

package portscan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// ScanModuleName is the object the daemon loads for this feature. It is built
// by ebpf_prog/Makefile.scan and installed alongside the other modules.
const ScanModuleName = "opensnitch-scan.o"

// scanProgramName is the entry point inside that object.
const scanProgramName = "tc_scan_ingress"

// Flags and anomaly bits shared with the eBPF program. They are duplicated
// here rather than generated; TestEbpfContractConstantsMatchC and
// TestEveryAnomalyBitExistsOnBothSides check the C source still agrees, so a
// change on one side cannot silently desynchronise them.
const (
	probeFlagHasMAC       = 1 << 0
	probeFlagTCPFlagsOK   = 1 << 1
	probeFlagIPv6         = 1 << 2
	probeAnomalyFragment  = 1 << 0
	probeAnomalyExtHdr    = 1 << 1
	probeAnomalyTruncated = 1 << 2
	probeAnomalyNoTCPOpts = 1 << 3
	probeAnomalyFirstFrag = 1 << 4
	probeAnomalyVLANDepth = 1 << 5
	probeAnomalyTrailer   = 1 << 6
)

// Indices into the config and stats arrays, mirroring the C side.
const (
	cfgEnabled        = 0
	cfgMaxPerSec      = 1
	cfgGraceUntilLo   = 2
	cfgGraceUntilHi   = 3
	cfgMaxTotalPerSec = 4
)

// probeEvent is the wire form of a probe as the eBPF program writes it.
// The layout must match struct probe_event in ebpf_prog/opensnitch-scan.c.
type probeEvent struct {
	TimeNs    uint64
	Saddr     [16]byte
	Daddr     [16]byte
	SrcMAC    [6]byte
	Sport     uint16
	Dport     uint16
	IfIndex   uint32
	Proto     uint8
	TCPFlags  uint8
	Anomalies uint16
	Flags     uint16
	Pad       uint16
}

// probeEventSize is the on-wire size of probeEvent. The C struct is packed, so
// binary.Size is the authority here, not unsafe.Sizeof of the Go struct.
var probeEventSize = binary.Size(probeEvent{})

// EbpfSource attaches the TC ingress program and reads its ring buffer.
type EbpfSource struct {
	mu   sync.Mutex
	coll *ebpf.Collection
	// links is one TCX link per attached interface, keyed by interface index so
	// an interface that goes away releases its link.
	links   map[int]link.Link
	reader  *ringbuf.Reader
	started time.Time
	closed  bool

	// ifaceNames is the operator's interface list, empty for "every usable one".
	// Kept so RefreshInterfaces can re-evaluate it.
	ifaceNames []string

	onProbe func(*Probe)
	onError func(error)

	// lastNowNs is the last successful CLOCK_MONOTONIC reading, and clockErr
	// whether the failure has already been reported. See NowNs.
	lastNowNs atomic.Uint64
	clockErr  atomic.Bool
}

// ErrEbpfUnavailable reports that the module could not be loaded or attached.
// Callers use it to decide whether falling back to AF_PACKET is appropriate.
var ErrEbpfUnavailable = errors.New("portscan: the eBPF scan module is unavailable")

// EbpfOptions configures the kernel source.
type EbpfOptions struct {
	// ModulesPath overrides where opensnitch-scan.o is looked for.
	ModulesPath string
	// Interfaces restricts attachment; empty means every interface that is up
	// and not loopback.
	Interfaces []string
	// MaxProbesPerSecond is the per-source forwarding budget. A scan of every
	// port would otherwise push 65535 records through the ring buffer, when
	// the engine needs only enough to cross its threshold and characterise the
	// technique.
	MaxProbesPerSecond uint32
	// MaxTotalPerSecond is the aggregate forwarding budget, applied per CPU. The
	// per-source budget bounds nothing in aggregate: a flood of forged addresses is
	// a stream of first packets, and a source never seen before is forwarded.
	MaxTotalPerSecond uint32
	// StartupGrace is how long after attachment TCP carrying ACK is not
	// forwarded: the packets of connections opened before detection started
	// (see Engine.accept).
	StartupGrace time.Duration
	// LocalAddrs and Exempt seed the kernel-side filters.
	LocalAddrs    []netip.Addr
	Exempt        []netip.Prefix
	ExcludedPorts []uint16
}

// NewEbpfSource loads, configures and attaches the module.
//
// Every failure of the module itself is wrapped in ErrEbpfUnavailable so the
// caller can fall back without having to pattern-match on error text. An
// interface list that matches nothing is ErrNoConfiguredInterface instead:
// falling back would not help.
func NewEbpfSource(opts EbpfOptions, onProbe func(*Probe), onError func(error)) (*EbpfSource, error) {
	if onProbe == nil {
		return nil, fmt.Errorf("portscan: NewEbpfSource requires an onProbe callback")
	}
	if onError == nil {
		onError = func(error) {}
	}
	if opts.MaxProbesPerSecond == 0 {
		opts.MaxProbesPerSecond = 256
	}
	if opts.MaxTotalPerSecond == 0 {
		opts.MaxTotalPerSecond = 4096
	}

	modulesPath, err := resolveScanModule(opts.ModulesPath)
	if err != nil {
		return nil, err
	}
	// Loaded here rather than through core.LoadEbpfModule, so that the file
	// that was verified is the file that is read. See loadScanModule.
	coll, err := loadScanModule(modulesPath)
	if err != nil {
		return nil, err
	}

	s := &EbpfSource{
		coll:       coll,
		started:    time.Now(),
		onProbe:    onProbe,
		onError:    onError,
		ifaceNames: append([]string(nil), opts.Interfaces...),
		links:      map[int]link.Link{},
	}

	if err := s.configure(opts); err != nil {
		s.Close()
		return nil, fmt.Errorf("%w: %v", ErrEbpfUnavailable, err)
	}
	if err := s.attach(opts.Interfaces); err != nil {
		s.Close()
		if errors.Is(err, ErrNoConfiguredInterface) {
			// The module is fine; the interface list matches nothing.
			// Reporting "the eBPF scan module is unavailable" would send
			// operators looking for a missing file.
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrEbpfUnavailable, err)
	}

	rb, ok := coll.Maps["scan_events"]
	if !ok {
		s.Close()
		return nil, fmt.Errorf("%w: the module has no scan_events ring buffer", ErrEbpfUnavailable)
	}
	rd, err := ringbuf.NewReader(rb)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("%w: opening the ring buffer: %v", ErrEbpfUnavailable, err)
	}
	s.reader = rd
	return s, nil
}

// configure fills the kernel-side maps.
func (s *EbpfSource) configure(opts EbpfOptions) error {
	put := func(name string, key, value interface{}) error {
		m, ok := s.coll.Maps[name]
		if !ok {
			return fmt.Errorf("the module has no map %q", name)
		}
		return m.Put(key, value)
	}

	// An absolute deadline in the clock bpf_ktime_get_ns() reads, not a duration:
	// compared against uptime, a duration would apply only in the machine's first
	// minute (TestLiveEbpfGraceDeadlineIsAbsolute).
	graceNs := s.NowNs() + uint64(opts.StartupGrace)
	if err := put("scan_config", uint32(cfgGraceUntilLo), uint32(graceNs)); err != nil {
		return err
	}
	if err := put("scan_config", uint32(cfgGraceUntilHi), uint32(graceNs>>32)); err != nil {
		return err
	}
	if err := put("scan_config", uint32(cfgMaxPerSec), opts.MaxProbesPerSecond); err != nil {
		return err
	}
	if err := put("scan_config", uint32(cfgMaxTotalPerSec), opts.MaxTotalPerSecond); err != nil {
		return err
	}

	for _, a := range opts.LocalAddrs {
		key := addrKey(a)
		if err := put("local_addrs", key, uint8(1)); err != nil {
			return fmt.Errorf("seeding local_addrs with %s: %w", a, err)
		}
	}
	for _, p := range opts.Exempt {
		if err := s.putExempt(p); err != nil {
			return err
		}
	}
	// excluded_ports is a bitmap over the whole port space, 1024 words of 64 bits:
	// an array lookup is inlined by the verifier where a hash lookup is a call on
	// every packet. Only non-zero words are written.
	var excluded [1024]uint64
	for _, port := range opts.ExcludedPorts {
		excluded[port>>6] |= 1 << (port & 63)
	}
	for i, w := range excluded {
		if w == 0 {
			continue
		}
		if err := put("excluded_ports", uint32(i), w); err != nil {
			return fmt.Errorf("seeding excluded_ports word %d: %w", i, err)
		}
	}

	// Enabled last, so the program never runs against a half-filled filter
	// set: an empty local_addrs map would make it discard every packet, and an
	// empty exempt trie would make it forward traffic it must never count.
	return put("scan_config", uint32(cfgEnabled), uint32(1))
}

// lpmKeyV4 and lpmKeyV6 mirror the C structs of the same shape.
type lpmKeyV4 struct {
	PrefixLen uint32
	Addr      [4]byte
}

type lpmKeyV6 struct {
	PrefixLen uint32
	Addr      [16]byte
}

func (s *EbpfSource) putExempt(p netip.Prefix) error {
	if p.Addr().Is4() {
		m, ok := s.coll.Maps["exempt_v4"]
		if !ok {
			return fmt.Errorf("the module has no map exempt_v4")
		}
		return m.Put(lpmKeyV4{PrefixLen: uint32(p.Bits()), Addr: p.Addr().As4()}, uint8(1))
	}
	m, ok := s.coll.Maps["exempt_v6"]
	if !ok {
		return fmt.Errorf("the module has no map exempt_v6")
	}
	return m.Put(lpmKeyV6{PrefixLen: uint32(p.Bits()), Addr: p.Addr().As16()}, uint8(1))
}

// addrKey renders an address as the 16-byte key the maps use, IPv4 stored as
// a v4-mapped address so one key type covers both families.
func addrKey(a netip.Addr) [16]byte {
	return a.Unmap().As16()
}

// attach hooks the program onto each interface's ingress path.
func (s *EbpfSource) attach(ifaceNames []string) error {
	prog, ok := s.coll.Programs[scanProgramName]
	if !ok {
		return fmt.Errorf("the module has no %s program", scanProgramName)
	}
	ifaces, missingIfaces, err := resolveInterfacesPartial(ifaceNames)
	if err == nil && len(ifaces) == 0 && len(missingIfaces) > 0 {
		err = fmt.Errorf("%w: %s", ErrNoConfiguredInterface, strings.Join(missingIfaces, ", "))
	}
	if err != nil {
		return err
	}
	if len(ifaces) == 0 {
		return fmt.Errorf("no usable interface to attach to")
	}

	var attached int
	var lastErr error
	for _, ifi := range ifaces {
		// TCX (kernel >= 6.6) allows several owners on one interface, which
		// matters because a single-owner attachment would put OpenSnitch in
		// conflict with any other tool using the ingress hook.
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: ifi.Index,
			Program:   prog,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			lastErr = fmt.Errorf("attaching to %s: %w", ifi.Name, err)
			continue
		}
		s.links[ifi.Index] = l
		attached++
	}

	if err := s.syncL2lessLocked(ifaces); err != nil {
		// Not fatal: the program still watches every Ethernet interface. But a
		// tunnel it cannot recognise is a tunnel it sees nothing on, which is
		// worth saying.
		s.onError(err)
	}
	if attached == 0 {
		return fmt.Errorf("could not attach to any interface: %w", lastErr)
	}
	reportMissingInterfaces(s.onError, missingIfaces)
	return nil
}

// RefreshInterfaces attaches the program to interfaces that have appeared or
// come up since the last call, releases those that have gone, and reports which
// it attached to (see Monitor.refreshSourceInterfaces). A failure on one new
// interface does not stop the others or touch what already works.
func (s *EbpfSource) RefreshInterfaces() ([]string, error) {
	// Missing names are not an error here: a VPN that is down has no interface
	// yet, and this refresh exists to pick it up.
	ifaces, _, err := resolveInterfacesPartial(s.ifaceNames)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coll == nil || s.closed {
		return nil, nil
	}
	prog, ok := s.coll.Programs[scanProgramName]
	if !ok {
		return nil, fmt.Errorf("portscan: the module has no %s program", scanProgramName)
	}

	live := make(map[int]bool, len(ifaces))
	for _, ifi := range ifaces {
		live[ifi.Index] = true
	}

	// Interfaces that have gone release their link, which also detaches the
	// program from an index the kernel may later hand to something else.
	var lastErr error
	for idx, l := range s.links {
		if live[idx] {
			continue
		}
		if err := l.Close(); err != nil {
			lastErr = fmt.Errorf("portscan: releasing the link for interface %d: %w", idx, err)
		}
		delete(s.links, idx)
	}

	var added []string
	for _, ifi := range ifaces {
		if _, ok := s.links[ifi.Index]; ok {
			continue
		}
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: ifi.Index,
			Program:   prog,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			lastErr = fmt.Errorf("portscan: attaching to %s: %w", ifi.Name, err)
			continue
		}
		s.links[ifi.Index] = l
		added = append(added, ifi.Name)
	}

	if err := s.syncL2lessLocked(ifaces); err != nil && lastErr == nil {
		lastErr = err
	}
	return added, lastErr
}

// syncL2lessLocked tells the program which interfaces carry no link header.
// s.mu must be held.
func (s *EbpfSource) syncL2lessLocked(ifaces []net.Interface) error {
	m, ok := s.coll.Maps["l2less_ifaces"]
	if !ok {
		return fmt.Errorf("portscan: the module has no l2less_ifaces map")
	}
	want := map[uint32]bool{}
	for _, ifi := range ifaces {
		if !hasLinkHeader(ifi) {
			want[uint32(ifi.Index)] = true
		}
	}

	var key uint32
	var value uint8
	var stale []uint32
	it := m.Iterate()
	for it.Next(&key, &value) {
		if !want[key] {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("portscan: walking the link-header map: %w", err)
	}
	var firstErr error
	for idx := range want {
		if err := m.Put(idx, uint8(1)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("portscan: marking interface %d as having no link header: %w", idx, err)
		}
	}
	for _, idx := range stale {
		if err := m.Delete(idx); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) && firstErr == nil {
			firstErr = fmt.Errorf("portscan: unmarking interface %d: %w", idx, err)
		}
	}
	return firstErr
}

// Run reads the ring buffer until Close.
func (s *EbpfSource) Run() {
	// One event and one Probe for the whole loop. See the Probe documentation:
	// it is valid only for the duration of the callback, which is what keeps
	// the packet path free of per-packet allocation.
	var (
		ev probeEvent
		p  Probe
	)
	for {
		rec, err := s.reader.Read()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if !closed && !errors.Is(err, ringbuf.ErrClosed) {
				s.onError(fmt.Errorf("portscan: reading the scan ring buffer: %w", err))
			}
			return
		}
		if len(rec.RawSample) < probeEventSize {
			continue
		}
		if err := decodeProbeEvent(rec.RawSample, &ev); err != nil {
			continue
		}
		if !ev.fill(&p) {
			continue
		}
		s.onProbe(&p)
	}
}

// fill overwrites p from the event, reporting whether the event was usable. It
// assigns the whole struct, so nothing carries over from the previous record
// decoded into the same Probe.
func (e *probeEvent) fill(p *Probe) bool {
	src, ok1 := netip.AddrFromSlice(e.Saddr[:])
	dst, ok2 := netip.AddrFromSlice(e.Daddr[:])
	if !ok1 || !ok2 {
		return false
	}
	*p = Probe{
		TimeNs:     e.TimeNs,
		Src:        src.Unmap(),
		Dst:        dst.Unmap(),
		SrcMAC:     e.SrcMAC,
		HasMAC:     e.Flags&probeFlagHasMAC != 0,
		Proto:      e.Proto,
		TCPFlags:   e.TCPFlags,
		SrcPort:    e.Sport,
		DstPort:    e.Dport,
		IfaceIndex: e.IfIndex,
	}
	// TCPFlagsValid is carried explicitly rather than inferred from a non-zero
	// flag byte: nmap -f leaves the flags unreadable, and a zero byte that was
	// never read must not be reported as a NULL scan.
	p.TCPFlagsValid = e.Flags&probeFlagTCPFlagsOK != 0

	if e.Anomalies&probeAnomalyFragment != 0 {
		p.Anomalies |= AnomalyFragment
	}
	if e.Anomalies&probeAnomalyExtHdr != 0 {
		p.Anomalies |= AnomalyExtHeaderChain
	}
	if e.Anomalies&probeAnomalyTruncated != 0 {
		p.Anomalies |= AnomalyTruncated
	}
	if e.Anomalies&probeAnomalyNoTCPOpts != 0 {
		p.Anomalies |= AnomalyNoTCPOptions
	}
	if e.Anomalies&probeAnomalyFirstFrag != 0 {
		p.Anomalies |= AnomalyFirstFragment
	}
	if e.Anomalies&probeAnomalyVLANDepth != 0 {
		p.Anomalies |= AnomalyVLANDepth
	}
	if e.Anomalies&probeAnomalyTrailer != 0 {
		p.Anomalies |= AnomalyTrailer
	}
	return true
}

// Close detaches the program and releases everything.
func (s *EbpfSource) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true

	// Everything below runs under the lock, so a concurrent Stats never reads
	// s.coll after it is cleared. ringbuf.Reader.Close does not call back into
	// EbpfSource.
	defer s.mu.Unlock()
	if s.reader != nil {
		_ = s.reader.Close()
	}
	for _, l := range s.links {
		_ = l.Close()
	}
	s.links = map[int]link.Link{}
	if s.coll != nil {
		s.coll.Close()
		s.coll = nil
	}
	return nil
}

// StartedAt reports when the source started. Probes carry bpf_ktime_get_ns()
// timestamps on another origin; the engine only compares them with each other,
// so this matters only for the wall-clock anchor.
func (s *EbpfSource) StartedAt() time.Time { return s.started }

// Stats reads the kernel-side counters, summed across CPUs; see
// Monitor.checkSourceDegradation.
func (s *EbpfSource) Stats() (map[string]uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coll == nil {
		// Close nils this out. Read unlocked, it would be a nil dereference in
		// a root daemon, reachable from any concurrent status query at shutdown.
		return nil, fmt.Errorf("portscan: the module is not loaded")
	}
	m, ok := s.coll.Maps["scan_stats"]
	if !ok {
		return nil, fmt.Errorf("portscan: the module has no scan_stats map")
	}
	// The index is the STAT_ constant in the program.
	names := []string{"seen", "forwarded", "filtered", "rate_limited", "ringbuf_full",
		"source_rate_limited"}
	out := make(map[string]uint64, len(names))
	for i, name := range names {
		var perCPU []uint64
		if err := m.Lookup(uint32(i), &perCPU); err != nil {
			continue
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		out[name] = total
	}
	return out, nil
}

// SyncLocalAddrs makes the kernel-side address map match addrs. The program
// keeps only packets aimed at one of these, and the set changes while the daemon
// runs (DHCP renewal, new interface, IPv6 privacy address). Additions come
// before removals, so an address the host still owns is never missing.
func (s *EbpfSource) SyncLocalAddrs(addrs []netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coll == nil || s.closed {
		return nil
	}
	m, ok := s.coll.Maps["local_addrs"]
	if !ok {
		return fmt.Errorf("portscan: the module has no local_addrs map")
	}

	want := make(map[[16]byte]bool, len(addrs))
	for _, a := range addrs {
		want[addrKey(a)] = true
	}

	// The stale entries are identified before anything is added, and removed even
	// when an addition failed: a full hash map answers E2BIG, and giving up on the
	// first failure would leave it full for good, with a new address that never
	// gets in and whose packets are all dropped.
	var (
		key   [16]byte
		value uint8
		stale [][16]byte
	)
	it := m.Iterate()
	for it.Next(&key, &value) {
		if !want[key] {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("portscan: walking the kernel address map: %w", err)
	}

	// Additions come first: an address the host still owns must never be
	// briefly absent. Removals of addresses it no longer owns can safely wait,
	// and go second, even after a failed addition, which is what stops the map
	// filling for ever.
	var firstErr error
	for key := range want {
		if err := m.Put(key, uint8(1)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("portscan: adding a local address to the kernel map"+
				" (it holds %d of %d entries): %w", len(want)+len(stale), m.MaxEntries(), err)
		}
	}
	for _, k := range stale {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) && firstErr == nil {
			firstErr = fmt.Errorf("portscan: removing a stale local address: %w", err)
		}
	}
	if firstErr != nil {
		// Retried on the next pass, a minute later, now that room has been made.
		return firstErr
	}
	return nil
}

// LocalAddrCount reports how many addresses the kernel-side map holds, so a
// caller can tell "detection is running" from "detection is running blind".
func (s *EbpfSource) LocalAddrCount() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coll == nil {
		return 0, fmt.Errorf("portscan: the module is not loaded")
	}
	m, ok := s.coll.Maps["local_addrs"]
	if !ok {
		return 0, fmt.Errorf("portscan: the module has no local_addrs map")
	}
	var (
		key   [16]byte
		value uint8
		n     int
	)
	it := m.Iterate()
	for it.Next(&key, &value) {
		n++
	}
	return n, it.Err()
}

// EnableKernelProgramStats switches on the kernel's accounting of eBPF program
// runs and runtime, and returns the handle that turns it off. It is global and
// costs two timestamp reads per run of every program, so it is off by default;
// it exists so this feature's cost can be measured.
func EnableKernelProgramStats() (io.Closer, error) {
	c, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		return nil, fmt.Errorf("portscan: enabling BPF run-time statistics: %w", err)
	}
	return c, nil
}

// ProgramRuntime reports how many times the scan program ran and how long it
// spent in total, from the kernel's own accounting (the program's fdinfo). Both
// are zero unless EnableKernelProgramStats is on.
func (s *EbpfSource) ProgramRuntime() (runCount uint64, total time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coll == nil {
		return 0, 0, fmt.Errorf("portscan: the module is not loaded")
	}
	prog, ok := s.coll.Programs[scanProgramName]
	if !ok {
		return 0, 0, fmt.Errorf("portscan: the module has no %s program", scanProgramName)
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", prog.FD()))
	if err != nil {
		return 0, 0, fmt.Errorf("portscan: reading the program's fdinfo: %w", err)
	}
	var ns uint64
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		v, perr := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if perr != nil {
			continue
		}
		switch strings.TrimSpace(key) {
		case "run_cnt":
			runCount = v
		case "run_time_ns":
			ns = v
		}
	}
	return runCount, time.Duration(ns), nil
}

// interfaceName resolves an index for reporting, returning "" when unknown.
func interfaceName(idx uint32) string {
	if idx == 0 {
		return ""
	}
	ifi, err := net.InterfaceByIndex(int(idx))
	if err != nil {
		return ""
	}
	return ifi.Name
}

var _ PacketSource = (*EbpfSource)(nil)

// Offsets of the fields of struct probe_event, verified against the compiled
// object; probeEventSize and TestProbeEventLayout keep them honest.
const (
	peOffTimeNs    = 0
	peOffSaddr     = 8
	peOffDaddr     = 24
	peOffSrcMAC    = 40
	peOffSport     = 46
	peOffDport     = 48
	peOffIfIndex   = 50
	peOffProto     = 54
	peOffTCPFlags  = 55
	peOffAnomalies = 56
	peOffFlags     = 58
	peOffPad       = 60
)

// decodeProbeEvent parses one ring buffer record.
func decodeProbeEvent(raw []byte, out *probeEvent) error {
	if len(raw) < probeEventSize {
		return fmt.Errorf("portscan: ring buffer record is %d bytes, want at least %d", len(raw), probeEventSize)
	}
	// Decoded by hand: binary.Read on a struct takes the reflection path and
	// allocates, on a path whose rate the sender chooses. Native byte order,
	// because the program runs on this host and writes in its order.
	out.TimeNs = binary.NativeEndian.Uint64(raw[peOffTimeNs:])
	copy(out.Saddr[:], raw[peOffSaddr:peOffSaddr+16])
	copy(out.Daddr[:], raw[peOffDaddr:peOffDaddr+16])
	copy(out.SrcMAC[:], raw[peOffSrcMAC:peOffSrcMAC+6])
	out.Sport = binary.NativeEndian.Uint16(raw[peOffSport:])
	out.Dport = binary.NativeEndian.Uint16(raw[peOffDport:])
	out.IfIndex = binary.NativeEndian.Uint32(raw[peOffIfIndex:])
	out.Proto = raw[peOffProto]
	out.TCPFlags = raw[peOffTCPFlags]
	out.Anomalies = binary.NativeEndian.Uint16(raw[peOffAnomalies:])
	out.Flags = binary.NativeEndian.Uint16(raw[peOffFlags:])
	out.Pad = binary.NativeEndian.Uint16(raw[peOffPad:])
	return nil
}

// NowNs implements PacketSource in the clock the program stamps probes from,
// CLOCK_MONOTONIC since boot. A failed read returns the last reading, never
// zero: zero would put the grace deadline in the machine's first minute and make
// Expire remove nothing.
func (s *EbpfSource) NowNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		if s.clockErr.CompareAndSwap(false, true) {
			s.onError(fmt.Errorf("portscan: reading CLOCK_MONOTONIC: %w", err))
		}
		return s.lastNowNs.Load()
	}
	now := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	s.lastNowNs.Store(now)
	return now
}
