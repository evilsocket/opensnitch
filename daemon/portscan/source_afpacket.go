//go:build linux

package portscan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ifaceSock is one bound interface: its socket, and the means to stop the loop
// reading it without stopping the others. Per interface because an interface can
// go away, and its socket and kernel receive buffer must go with it.
type ifaceSock struct {
	fd   int
	name string
	// stop asks this loop to return; done is closed when it has.
	stop chan struct{}
	done chan struct{}
	// hasLinkHeader is false for ARPHRD_NONE devices -- tun, ppp, sit, gre,
	// xfrm -- whose frames begin at the IP header with no Ethernet header.
	hasLinkHeader bool
	// reading is true once a goroutine owns this socket, so closing knows
	// whether there is anyone to wait for.
	reading bool
}

// AFPacketSource feeds the engine from AF_PACKET raw sockets.
//
// It is the fallback for hosts where the eBPF module cannot be loaded. It
// copies every matching frame to user space, so it costs more, but it feeds
// the same engine and reaches the same verdicts. Two choices differ from the
// reference implementations:
//
//   - SOCK_RAW, not SOCK_DGRAM (PortSentry, sentry_stealth.c:59-67), which
//     would strip the Ethernet header and with it the source MAC;
//   - a kernel-side classic BPF filter that narrows by ethertype and link-layer
//     destination only, never by protocol or flags, so no scan technique is
//     filtered out before the parser sees it.
type AFPacketSource struct {
	mu      sync.Mutex
	socks   map[int]*ifaceSock
	closed  bool
	started time.Time

	// names is the operator's interface list, empty for "every usable one".
	// Kept so RefreshInterfaces can re-evaluate it.
	names []string
	// running reports that Run has started the read loops, so RefreshInterfaces
	// knows whether to start one for a socket it opens.
	running bool

	// snapLen bounds how much of each frame is copied. It must cover every
	// header the parser can legitimately have to walk; see afPacketSnapLen.
	snapLen int

	// budget caps how many parsed probes per second reach the engine, across
	// every interface; zero means no cap. It is what bounds the CPU a remote sender
	// can make this path spend, as global_allow does for the eBPF path. Counted
	// here rather than in the classic BPF filter, which cannot keep a time window:
	// a fixed sampling ratio would decide in advance how much of a slow scan to
	// miss.
	budget atomicWindow
	// sources holds each source to its own budget before the aggregate is
	// charged, as the kernel program does; see admit.
	sources *sourceWindows
	// overflow is the per-source budget shared by the sources that found both
	// their slots in use; see admit.
	overflow atomicWindow

	// drops counts probes refused by the aggregate budget, and sourceDrops
	// those refused by a source's own, for SourceStats.
	drops       atomic.Uint64
	sourceDrops atomic.Uint64
	// kernelDrops accumulates the kernel's own receive-buffer overflow counter,
	// which PACKET_STATISTICS resets on every read.
	kernelDrops atomic.Uint64

	// wg tracks the read loops so Close can wait for them before closing the
	// descriptors out from under an in-flight syscall.
	wg sync.WaitGroup

	onProbe func(*Probe)
	onError func(error)
}

// afPacketSnapLen must cover everything the parser can be required to walk: an
// Ethernet header, two VLAN tags, a 40-byte IPv6 header, the whole bounded
// extension-header chain, and a 60-byte TCP header. The parser bounds where the
// chain ends, not only where each header starts, so anything it accepts fits;
// TestEveryAcceptedExtensionChainFitsTheSnapLength holds the two together. A
// TCP header past the snap length would be seen by the kernel path and not by
// this one.
const afPacketSnapLen = ethHeaderLen + maxVLANTags*vlanTagLen + 40 + maxExtChainBytes + 60

// afPacketReadTimeout is how long a read loop blocks before checking whether it
// has been asked to stop. shutdown(2) does not wake an AF_PACKET socket, and
// closing the descriptor under an in-flight read risks its number being reused,
// so the loop has to wake on its own.
const afPacketReadTimeout = 250 * time.Millisecond

// htons converts a uint16 to network byte order for the socket protocol field,
// through NativeEndian: a plain byte swap is right only on little-endian hosts.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// ipOnlyFilter is a classic BPF program accepting only IPv4 and IPv6 frames
// addressed to this host at the link layer, including through one or two VLAN
// tags. Written out rather than compiled from a pcap expression, so the daemon
// needs no libpcap and the filter can be reviewed here. Rejecting broadcast and
// multicast in the kernel spares a copy of most of what a busy segment carries.
//
//	 (0) ldb   [SKF_AD_OFF+SKF_AD_PKTTYPE]
//	 (1) jeq   #PACKET_HOST  jt 2  jf 12 ; not for us -> drop
//	 (2) ldh   [12]                 ; ethertype
//	 (3) jeq   #0x0800  jt 11 jf 4  ; IPv4 -> accept
//	 (4) jeq   #0x86dd  jt 11 jf 5  ; IPv6 -> accept
//	 (5) jeq   #0x8100  jt 7  jf 6  ; 802.1Q -> look past the tag
//	 (6) jeq   #0x88a8  jt 7  jf 12 ; QinQ   -> look past the tag
//	 (7) ldh   [16]                 ; inner ethertype
//	 (8) jeq   #0x0800  jt 11 jf 9
//	 (9) jeq   #0x86dd  jt 11 jf 10
//	(10) jeq   #0x8100  jt 11 jf 12 ; second tag: accept and let the parser walk it
//	(11) ret   #262144              ; accept, truncated to snapLen by the socket
//	(12) ret   #0                   ; drop
var ipOnlyFilter = []unix.SockFilter{
	{Code: 0x30, Jt: 0, Jf: 0, K: skfADOff + skfADPktType},
	{Code: 0x15, Jt: 0, Jf: 10, K: unix.PACKET_HOST},
	{Code: 0x28, Jt: 0, Jf: 0, K: 12},
	{Code: 0x15, Jt: 7, Jf: 0, K: 0x0800},
	{Code: 0x15, Jt: 6, Jf: 0, K: 0x86dd},
	{Code: 0x15, Jt: 1, Jf: 0, K: 0x8100},
	{Code: 0x15, Jt: 0, Jf: 5, K: 0x88a8},
	{Code: 0x28, Jt: 0, Jf: 0, K: 16},
	{Code: 0x15, Jt: 2, Jf: 0, K: 0x0800},
	{Code: 0x15, Jt: 1, Jf: 0, K: 0x86dd},
	{Code: 0x15, Jt: 0, Jf: 1, K: 0x8100},
	{Code: 0x06, Jt: 0, Jf: 0, K: 0x40000},
	{Code: 0x06, Jt: 0, Jf: 0, K: 0},
}

// Ancillary-data offsets for classic BPF. The kernel maps loads at these
// negative offsets -- expressed as a large unsigned K -- to packet metadata
// rather than packet bytes; SKF_AD_PKTTYPE yields the sll.Pkttype value.
// linux/filter.h defines SKF_AD_OFF as -0x1000 and SKF_AD_PKTTYPE as 4.
const (
	skfADOff     = 0xfffff000 // (uint32)(-4096)
	skfADPktType = 4
)

// ipVersionFilter is ipOnlyFilter for an interface with no link header, where
// the frame begins at the IP header: it tests the version nibble, the only thing
// present. The socket still reports the real ethertype in sll.Protocol, which
// the read loop uses.
//
//	(0) ldb   [SKF_AD_OFF+SKF_AD_PKTTYPE]
//	(1) jeq   #PACKET_HOST  jt 2  jf 6 ; not for us -> drop
//	(2) ldb   [0]                  ; version and IHL
//	(3) and   #0xf0
//	(4) jeq   #0x40  jt 7  jf 5    ; IPv4 -> accept
//	(5) jeq   #0x60  jt 7  jf 6    ; IPv6 -> accept
//	(6) ret   #0                   ; drop
//	(7) ret   #262144              ; accept
var ipVersionFilter = []unix.SockFilter{
	{Code: 0x30, Jt: 0, Jf: 0, K: skfADOff + skfADPktType},
	{Code: 0x15, Jt: 0, Jf: 4, K: unix.PACKET_HOST},
	{Code: 0x30, Jt: 0, Jf: 0, K: 0},
	{Code: 0x54, Jt: 0, Jf: 0, K: 0xf0},
	{Code: 0x15, Jt: 2, Jf: 0, K: 0x40},
	{Code: 0x15, Jt: 1, Jf: 0, K: 0x60},
	{Code: 0x06, Jt: 0, Jf: 0, K: 0},
	{Code: 0x06, Jt: 0, Jf: 0, K: 0x40000},
}

// atomicWindow is a one-second token budget shared by every read loop,
// lock-free because every frame on every interface passes through it. The
// window rolls under the same asymmetric rule as the kernel's window_rolled: a
// timestamp slightly behind the window start is skew between goroutines, not a
// new window.
type atomicWindow struct {
	limit     uint32
	startNs   atomic.Uint64
	spent     atomic.Uint32
	rollMutex sync.Mutex
}

// allow reports whether one more probe fits in the current window.
func (w *atomicWindow) allow(nowNs uint64) bool {
	if w.limit == 0 {
		return true
	}
	start := w.startNs.Load()
	if windowRolled(start, nowNs, uint64(time.Second)) {
		// One goroutine rolls; the others fall through and count against the
		// window it opened, which is what they would have done had they
		// arrived a moment later.
		w.rollMutex.Lock()
		if w.startNs.Load() == start {
			w.startNs.Store(nowNs)
			w.spent.Store(0)
		}
		w.rollMutex.Unlock()
	}
	return w.spent.Add(1) <= w.limit
}

// afPacketSourceSlots is the size of the per-source budget table, and
// afPacketPerSourceBudget each source's budget per second: the kernel
// program's default MaxProbesPerSecond.
const (
	afPacketSourceSlots     = 4096
	afPacketPerSourceBudget = 256
)

// sourceWindows is the per-source budget: a fixed table in which each source
// may use one of two slots, picked by a keyed hash of its address. A source
// never seen before takes a candidate slot only if it is free or its window
// has ended: a slot still in use is not taken over. Taking it over would give
// the holder a fresh window on every packet from the other source, so two
// sources sharing a slot would let a busy peer spend the aggregate again. The
// sources that find both their slots in use share one per-source budget. The
// seed is random so a sender cannot choose addresses that share a peer's
// slots.
type sourceWindows struct {
	seed  maphash.Seed
	slots [afPacketSourceSlots]sourceWindow
}

type sourceWindow struct {
	mu      sync.Mutex
	addr    netip.Addr
	startNs uint64
	sent    uint32
	// lastNs is when the source last sent, for running.
	lastNs uint64
}

// candidates are the indices of the two slots addr may use.
func (w *sourceWindows) candidates(addr netip.Addr) (int, int) {
	b := addr.As16()
	h := maphash.Bytes(w.seed, b[:])
	return int(h % afPacketSourceSlots), int((h >> 32) % afPacketSourceSlots)
}

// running reports whether the slot holds a source that has sent in the last
// second. Its window's start would not do: the window rolls on the source's
// next packet, so a newcomer arriving just after a second ended, before that
// packet, would take the slot of a source sending thousands a second.
func (sw *sourceWindow) running(nowNs uint64) bool {
	return sw.addr.IsValid() && !windowRolled(sw.lastNs, nowNs, uint64(time.Second))
}

// initBudgets sets up both budgets; total is the aggregate, zero for none.
func (s *AFPacketSource) initBudgets(total uint32) {
	s.budget.limit = total
	s.sources = &sourceWindows{seed: maphash.MakeSeed()}
	s.overflow.limit = afPacketPerSourceBudget
}

// admit applies both budgets to a probe from src, in the order the kernel
// program uses (see budgets_check there). A known source is judged by its own
// budget first and the aggregate is charged only for what survives it: with
// the aggregate alone, one peer's download spent it and every other source,
// a scan included, lost its probes. A source never seen before asks the
// aggregate before it is given a budget, so a flood of forged sources, each
// new, is still capped.
func (s *AFPacketSource) admit(src netip.Addr, nowNs uint64) bool {
	i, j := s.sources.candidates(src)
	x, y := &s.sources.slots[i], &s.sources.slots[j]
	// Both slots are locked, lower index first, so two sources never wait on
	// each other.
	if i > j {
		x, y = y, x
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if y != x {
		y.mu.Lock()
		defer y.mu.Unlock()
	}
	w := x
	if w.addr != src {
		w = y
	}
	if w.addr != src {
		switch {
		case !x.running(nowNs):
			w = x
		case !y.running(nowNs):
			w = y
		default:
			// Both slots in use. Admitted on the aggregate alone, a busy
			// source in this position spent it for everyone; the sources in
			// it share one per-source budget instead. Its refusals are
			// counted with the aggregate's, and reported: under a flood of
			// forged addresses every slot is in use, and nearly every source
			// is refused here, a real scanner's included.
			if !s.overflow.allow(nowNs) {
				s.drops.Add(1)
				return false
			}
			w = nil
		}
		if !s.budget.allow(nowNs) {
			s.drops.Add(1)
			return false
		}
		if w != nil {
			w.addr, w.startNs, w.sent, w.lastNs = src, nowNs, 1, nowNs
		}
		return true
	}
	if nowNs > w.lastNs {
		w.lastNs = nowNs
	}
	if windowRolled(w.startNs, nowNs, uint64(time.Second)) {
		w.startNs, w.sent = nowNs, 0
	}
	if w.sent >= afPacketPerSourceBudget {
		s.sourceDrops.Add(1)
		return false
	}
	w.sent++
	if !s.budget.allow(nowNs) {
		s.drops.Add(1)
		return false
	}
	return true
}

// budgetStats is what the budgets refused; see Stats.
func (s *AFPacketSource) budgetStats() map[string]uint64 {
	return map[string]uint64{
		"rate_limited":        s.drops.Load(),
		"source_rate_limited": s.sourceDrops.Load(),
	}
}

// NewAFPacketSource opens one socket per named interface. An empty list means
// every interface that is up and not loopback.
//
// onProbe is called for every parsed inbound packet, from one goroutine per
// interface, so the engine it feeds must be safe for concurrent use (it is).
func NewAFPacketSource(ifaceNames []string, maxTotalPerSecond uint32, onProbe func(*Probe), onError func(error)) (*AFPacketSource, error) {
	if onProbe == nil {
		return nil, fmt.Errorf("portscan: NewAFPacketSource requires an onProbe callback")
	}
	if onError == nil {
		onError = func(error) {}
	}
	ifaces, missingIfaces, err := resolveInterfacesPartial(ifaceNames)
	if err == nil && len(ifaces) == 0 && len(missingIfaces) > 0 {
		err = fmt.Errorf("%w: %s", ErrNoConfiguredInterface, strings.Join(missingIfaces, ", "))
	}
	if err != nil {
		return nil, err
	}
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("portscan: no usable interface to listen on")
	}

	s := &AFPacketSource{
		snapLen: afPacketSnapLen,
		onProbe: onProbe,
		onError: onError,
		started: time.Now(),
		names:   append([]string(nil), ifaceNames...),
		socks:   map[int]*ifaceSock{},
	}
	s.initBudgets(maxTotalPerSecond)
	for _, ifi := range ifaces {
		if err := s.bindLocked(ifi); err != nil {
			s.Close()
			return nil, err
		}
	}
	reportMissingInterfaces(onError, missingIfaces)
	return s, nil
}

// hasLinkHeader reports whether frames on ifi begin with an Ethernet header.
// A tun device, ppp0, sit0, gre and xfrm do not: the kernel reports ARPHRD_NONE
// and a zero-length address for them, which net.Interface surfaces as an empty
// HardwareAddr. Loopback has an all-zero address, which net.Interface also
// leaves empty, but its frames do carry an Ethernet header.
func hasLinkHeader(ifi net.Interface) bool {
	return len(ifi.HardwareAddr) > 0 || ifi.Flags&net.FlagLoopback != 0
}

// bindLocked opens and records a socket for one interface. s.mu must be held,
// or the source must not be shared yet.
func (s *AFPacketSource) bindLocked(ifi net.Interface) error {
	hasL2 := hasLinkHeader(ifi)
	fd, err := openPacketSocket(ifi.Index, hasL2)
	if err != nil {
		return fmt.Errorf("portscan: opening a packet socket on %s: %w", ifi.Name, err)
	}
	s.socks[ifi.Index] = &ifaceSock{
		fd:            fd,
		name:          ifi.Name,
		hasLinkHeader: hasL2,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	return nil
}

// startLocked hands a socket to a read loop. s.mu must be held.
func (s *AFPacketSource) startLocked(sk *ifaceSock) {
	if sk.reading {
		return
	}
	sk.reading = true
	// Under s.wg like every other loop, so Close still waits for all of them
	// before closing any descriptor.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(sk.done)
		s.readLoop(sk)
	}()
}

// RefreshInterfaces binds to interfaces that have appeared or come up since the
// last call, releases those that have gone, and reports which it started on.
// See Monitor.refreshSourceInterfaces.
func (s *AFPacketSource) RefreshInterfaces() ([]string, error) {
	// Missing names are not an error here: a VPN that is down simply has no
	// interface yet, and this refresh exists to pick it up when it comes
	// back. Giving up on the whole list would leave every other interface
	// unattached and every vanished one unreleased.
	ifaces, _, err := resolveInterfacesPartial(s.names)
	if err != nil {
		return nil, err
	}
	live := make(map[int]bool, len(ifaces))
	for _, ifi := range ifaces {
		live[ifi.Index] = true
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil
	}

	// Interfaces that have gone are dropped from the map here, and released
	// below without the lock: stopping a read loop means waiting for it, and a
	// loop that has just hit an error takes this same lock on its way out.
	var gone []*ifaceSock
	for idx, sk := range s.socks {
		if !live[idx] {
			gone = append(gone, sk)
			delete(s.socks, idx)
		}
	}

	var added []string
	var bindErr error
	for _, ifi := range ifaces {
		if _, ok := s.socks[ifi.Index]; ok {
			continue
		}
		if err := s.bindLocked(ifi); err != nil {
			bindErr = err
			continue
		}
		added = append(added, ifi.Name)
		if s.running {
			s.startLocked(s.socks[ifi.Index])
		}
	}
	s.mu.Unlock()

	for _, sk := range gone {
		s.release(sk)
	}
	return added, bindErr
}

// release stops the loop reading a socket, waits for it, and closes the
// descriptor; it must be called without s.mu held. Closing first would free the
// number while a read is still using it. The wait is bounded by the receive
// timeout.
func (s *AFPacketSource) release(sk *ifaceSock) {
	close(sk.stop)
	if sk.reading {
		<-sk.done
	}
	if err := unix.Close(sk.fd); err != nil {
		s.onError(fmt.Errorf("portscan: closing the packet socket for %s: %w", sk.name, err))
	}
}

// resolveInterfaces turns the configured names into interfaces. A name that is
// not there is not an error -- a VPN may be down at boot -- and must not switch
// detection off on the interfaces that exist; missing names are reported and
// retried by the periodic refresh. Only a list where nothing resolves is an
// error.
func resolveInterfaces(names []string) ([]net.Interface, error) {
	out, missing, err := resolveInterfacesPartial(names)
	if err != nil {
		return nil, err
	}
	if len(missing) > 0 && len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoConfiguredInterface, strings.Join(missing, ", "))
	}
	return out, nil
}

// ErrNoConfiguredInterface is returned when Interfaces names interfaces and
// none of them exists. It is about the configuration, not about either packet
// source, so it is neither wrapped in ErrEbpfUnavailable nor a reason to fall
// back from one source to the other: both would fail on the same list.
var ErrNoConfiguredInterface = errors.New("portscan: none of the configured interfaces exist")

// reportMissingInterfaces says which configured interfaces a source started
// without, as a degradation: watching part of what was asked for is right,
// doing it silently is not.
func reportMissingInterfaces(onError func(error), missing []string) {
	if len(missing) == 0 {
		return
	}
	onError(degraded("configured interface(s) not present: %s;"+
		" they will be watched when they appear", strings.Join(missing, ", ")))
}

// resolveInterfacesPartial is resolveInterfaces without the "nothing resolved"
// judgement, so callers that can report progress do so.
func resolveInterfacesPartial(names []string) (found []net.Interface, missing []string, err error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("portscan: listing interfaces: %w", err)
	}
	if len(names) > 0 {
		out := make([]net.Interface, 0, len(names))
		for _, want := range names {
			ok := false
			for _, ifi := range all {
				if ifi.Name == want {
					out = append(out, ifi)
					ok = true
					break
				}
			}
			if !ok {
				missing = append(missing, want)
			}
		}
		return out, missing, nil
	}
	out := make([]net.Interface, 0, len(all))
	for _, ifi := range all {
		// Loopback is excluded: a host cannot scan itself over lo in any way
		// this feature is meant to catch, and including it would make every
		// local service probe look like reconnaissance.
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		out = append(out, ifi)
	}
	return out, nil, nil
}

func openPacketSocket(ifIndex int, hasLinkHeader bool) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}
	// Attach the filter before binding, so that no unfiltered packet can be
	// queued between the two calls.
	filter := ipOnlyFilter
	if !hasLinkHeader {
		// An interface with no hardware address carries no link header, so the
		// frame begins at the IP header. ipOnlyFilter reads bytes 12-13 as an
		// ethertype; on such a device those are two bytes of the source address,
		// so it would reject every packet of every tunnel.
		filter = ipVersionFilter
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("attaching the packet filter: %w", err)
	}
	// A receive timeout is what lets Close stop the read loops: shutdown(2)
	// does nothing on AF_PACKET, so without it a loop parked in Recvfrom on a
	// silent interface never returns and Monitor.Stop blocks for ever.
	tv := unix.NsecToTimeval(int64(afPacketReadTimeout))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("setting the receive timeout: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifIndex,
	}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("binding to interface index %d: %w", ifIndex, err)
	}
	return fd, nil
}

// Run reads packets until Close is called. It blocks, and is meant to be
// started in its own goroutine.
func (s *AFPacketSource) Run() {
	s.mu.Lock()
	// From here on RefreshInterfaces starts a loop for every socket it opens,
	// which is what makes an interface that comes up later actually watched
	// rather than merely bound.
	s.running = true
	for _, sk := range s.socks {
		s.startLocked(sk)
	}
	s.mu.Unlock()

	s.wg.Wait()
}

func (s *AFPacketSource) readLoop(sk *ifaceSock) {
	fd := sk.fd
	buf := make([]byte, s.snapLen)
	// One Probe for the whole loop. See the Probe documentation: it is valid
	// only for the duration of the callback, which is what keeps the packet
	// path free of per-packet allocation -- otherwise a scanner would decide
	// how often this daemon's garbage collector runs.
	var p Probe
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				// The receive timeout fired: nothing arrived. This is the
				// only thing that makes a parked loop notice that it has been
				// asked to stop -- either the whole source closing, or just
				// this interface going away.
				if s.stopping(sk) {
					return
				}
				continue
			}
			if !s.stopping(sk) {
				s.onError(fmt.Errorf("portscan: reading from the packet socket on %s: %w", sk.name, err))
			}
			return
		}
		sll, ok := from.(*unix.SockaddrLinklayer)
		if !ok {
			continue
		}
		// Only packets actually addressed to this host. PACKET_OUTGOING would
		// otherwise feed our own replies back into detection, and
		// PACKET_BROADCAST / PACKET_MULTICAST are not probes of one of our
		// unicast addresses. PortSentry applies the same filter
		// (sentry_stealth.c:150).
		if sll.Pkttype != unix.PACKET_HOST {
			continue
		}

		// Whole-struct assignment, so every field is reset by construction:
		// enumerating the ones to clear is how a stale flag from the previous
		// packet ends up attributed to this one.
		p = Probe{
			TimeNs:     uint64(time.Since(s.started)),
			IfaceIndex: uint32(sll.Ifindex),
		}
		// A parse error is not a reason to drop the probe: whatever was recovered is
		// reported with the anomaly saying what was not, and the engine decides what it
		// is worth. An interface with no link header hands over the IP packet
		// directly.
		if sk.hasLinkHeader {
			_ = ParseEthernet(buf[:n], &p)
		} else {
			_ = ParseIP(buf[:n], &p)
		}
		if !p.Src.IsValid() {
			continue
		}
		// The budgets, after the parse since the per-source one needs the
		// address: the parse is bounded by the snap length, and it is the
		// engine the budgets keep a sender from driving. See admit.
		if !s.admit(p.Src, p.TimeNs) {
			continue
		}
		s.onProbe(&p)
	}
}

// stopping reports whether this loop has been asked to return, either because
// the whole source is closing or because its interface has gone away.
func (s *AFPacketSource) stopping(sk *ifaceSock) bool {
	select {
	case <-sk.stop:
		return true
	default:
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	return closed
}

// Close stops every read loop and releases the sockets.
func (s *AFPacketSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	socks := s.socks
	s.socks = map[int]*ifaceSock{}
	s.mu.Unlock()

	// Wait for the read loops to notice before closing anything. shutdown(2)
	// does nothing on an AF_PACKET socket, so the loops are woken by their
	// receive timeout, not by us; closing the descriptors first would free the
	// numbers while a syscall is still using them, and another goroutine's open
	// could take one and be read from by a loop that has not stopped yet.
	s.wg.Wait()

	var firstErr error
	for _, sk := range socks {
		if err := unix.Close(sk.fd); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	s.mu.Lock() // restore the deferred unlock's expectation
	return firstErr
}

// StartedAt reports the monotonic origin the source uses for Probe.TimeNs, so
// the engine can be created with a matching start time.
func (s *AFPacketSource) StartedAt() time.Time { return s.started }

// NowNs implements PacketSource in the same clock readLoop stamps probes from.
func (s *AFPacketSource) NowNs() uint64 { return uint64(time.Since(s.started)) }

// afPacketDefaultBudget is the aggregate cap on probes reaching the engine from
// this source, per second, across every interface. It matches the eBPF path's
// MaxTotalPerSecond (applied there per CPU, here per process): far more than any
// real scan produces, far less than a flood.
const afPacketDefaultBudget = 4096

// Stats implements SourceStats, so a degraded fallback is visible:
//
//   - rate_limited: probes refused because the aggregate budget was spent;
//   - source_rate_limited: probes refused by their source's own budget;
//   - kernel_dropped: frames the kernel discarded because the socket's receive
//     buffer was full (PACKET_STATISTICS, reset on every read, so accumulated
//     here).
//
// The first two carry the kernel program's names, so the monitor reads both
// sources alike.
func (s *AFPacketSource) Stats() (map[string]uint64, error) {
	s.mu.Lock()
	// socks is keyed by interface index; the descriptor is in the value.
	fds := make([]int, 0, len(s.socks))
	for _, sk := range s.socks {
		fds = append(fds, sk.fd)
	}
	closed := s.closed
	s.mu.Unlock()

	if closed {
		return nil, fmt.Errorf("portscan: the packet source is closed")
	}

	var kernelDropped uint64
	var failed int
	var firstErr error
	for _, fd := range fds {
		st, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
		if err != nil {
			// Counted and surfaced, never swallowed: a failure discarded here
			// would leave the counter at zero for ever, which is exactly what a
			// packet source losing nothing looks like.
			failed++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		kernelDropped += uint64(st.Drops)
	}
	s.kernelDrops.Add(kernelDropped)

	out := s.budgetStats()
	out["kernel_dropped"] = s.kernelDrops.Load()
	if failed > 0 {
		return out, fmt.Errorf("portscan: could not read receive-buffer statistics for"+
			" %d of %d packet socket(s): %w", failed, len(fds), firstErr)
	}
	return out, nil
}
