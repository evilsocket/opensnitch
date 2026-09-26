//go:build linux

package portscan

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evilsocket/opensnitch/daemon/netstat"
)

// SystemHostInfo is the production HostInfo: it answers the engine's questions
// from the live state of this machine, always from a snapshot refreshed on a
// timer and never on the packet path, so a scan cannot make the host re-read
// /proc per packet.
type SystemHostInfo struct {
	mu sync.RWMutex

	// localAddrs are this host's own unicast addresses.
	localAddrs map[netip.Addr]bool
	// onLink are the prefixes directly attached to an interface.
	onLink []netip.Prefix
	// listening is the set of local sockets in a listening state, keyed by
	// protocol and port.
	listening map[listenKey]bool
	// established is the set of connections this host already knows about,
	// keyed by the four-tuple as seen from the remote end.
	established map[flowKey]bool
	// exempt are prefixes that must never be counted or blocked.
	exempt []netip.Prefix
	// operatorExempt is the configured half, kept so a refresh can rebuild the
	// list without losing it.
	operatorExempt []netip.Prefix
	// neverBlock is the operator's never-block list. Unlike exempt, it does
	// NOT suppress detection: see IsNeverBlock.
	neverBlock []netip.Prefix
	// infra is the derived half: next hops and resolvers. Never configurable.
	infra infrastructure
	// infraErr holds the failure of the last infrastructure read, if any. See
	// InfraError.
	infraErr atomic.Pointer[error]
	// onError reports refresh failures. See SetOnError.
	onError atomic.Pointer[func(error)]

	refreshEvery time.Duration
	stop         chan struct{}
	stopped      bool
}

type listenKey struct {
	proto uint8
	port  uint16
}

// flowKey identifies a connection from the point of view of an inbound packet:
// the remote end is the source, the local end is the destination.
type flowKey struct {
	proto      uint8
	remote     netip.Addr
	remotePort uint16
	local      netip.Addr
	localPort  uint16
}

// NewSystemHostInfo builds a host view and performs the first refresh
// synchronously, so the engine is never fed from an empty snapshot -- which
// would make every packet look like a probe to a closed port on an address
// that is not ours.
func NewSystemHostInfo(exempt []netip.Prefix, refreshEvery time.Duration) (*SystemHostInfo, error) {
	if refreshEvery <= 0 {
		refreshEvery = 10 * time.Second
	}
	h := &SystemHostInfo{
		localAddrs:   map[netip.Addr]bool{},
		listening:    map[listenKey]bool{},
		established:  map[flowKey]bool{},
		refreshEvery: refreshEvery,
		stop:         make(chan struct{}),
	}
	h.setExempt(exempt)
	if err := h.Refresh(); err != nil {
		// An infrastructure read that failed is recorded and reported, not fatal:
		// refusing to start would give anything that can break one of those files (a
		// DHCP server writes the `search` line) an off switch. ExpireDue releases any
		// block later found to be on infrastructure.
		//
		// A failure to read the host's own addresses is fatal: without them
		// Engine.accept discards every packet and detection would report itself active
		// while seeing nothing.
		if errors.Is(err, ErrHostAddresses) {
			return nil, err
		}
		h.infraErr.Store(&err)
	}
	return h, nil
}

// ErrHostAddresses reports that this host's own addresses could not be read.
//
// Separate from the infrastructure errors because the consequence is different
// in kind: an incomplete never-block list degrades a protection, while an empty
// address set removes detection altogether.
var ErrHostAddresses = errors.New("portscan: the host's own addresses could not be read")

// LocalAddrCount is how many local unicast addresses the view holds. Zero is
// not an error -- the network may not be up yet -- but nothing can be detected
// in that state, so the monitor watches it.
func (h *SystemHostInfo) LocalAddrCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.localAddrs)
}

// InfraError returns the failure of the last infrastructure read, or nil.
//
// A non-nil value means the never-block list may be incomplete: the addresses
// this host needs in order to have a network at all are derived from files that
// could not be read in full.
func (h *SystemHostInfo) InfraError() error {
	if p := h.infraErr.Load(); p != nil {
		return *p
	}
	return nil
}

// SetOnError registers a callback for refresh failures.
//
// Without one, a periodic refresh that fails is invisible: the daemon keeps
// running on the last good snapshot and nothing says the never-block list may
// have stopped tracking the network.
func (h *SystemHostInfo) SetOnError(f func(error)) {
	h.onError.Store(&f)
}

func (h *SystemHostInfo) reportError(err error) {
	if f := h.onError.Load(); f != nil && *f != nil {
		(*f)(err)
	}
}

// Start begins periodic refreshes.
func (h *SystemHostInfo) Start() {
	go func() {
		t := time.NewTicker(h.refreshEvery)
		defer t.Stop()
		for {
			select {
			case <-h.stop:
				return
			case <-t.C:
				if err := h.Refresh(); err != nil {
					h.reportError(err)
				}
			}
		}
	}()
}

// Stop ends the refresh loop.
func (h *SystemHostInfo) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.stopped {
		h.stopped = true
		close(h.stop)
	}
}

// SetExempt replaces the never-count prefix list.
func (h *SystemHostInfo) SetExempt(prefixes []netip.Prefix) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.setExemptLocked(prefixes)
}

func (h *SystemHostInfo) setExempt(prefixes []netip.Prefix) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.setExemptLocked(prefixes)
}

// setExemptLocked installs the operator list on top of the mandatory entries,
// which are not configurable: no configuration mistake may make the host count
// its own loopback, or multicast and broadcast sources. The link-local ranges
// are never blocked rather than never counted; see mandatoryNeverBlock (psad
// had to add the same kind of guard after the fact, ChangeLog:1111).
func (h *SystemHostInfo) setExemptLocked(prefixes []netip.Prefix) {
	h.operatorExempt = append([]netip.Prefix(nil), prefixes...)
	h.exempt = append(append([]netip.Prefix(nil), mandatoryNeverCount...), prefixes...)
}

// mandatoryNeverCount are source addresses whose packets are never scored:
// only those whose traffic cannot be a scan of this host -- our loopback, and
// multicast or broadcast sources. Engine.accept refuses most of them already;
// the kernel program gets this list and drops them before user space.
var mandatoryNeverCount = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"), // loopback
	netip.MustParsePrefix("::1/128"),     // loopback
	netip.MustParsePrefix("224.0.0.0/4"), // IPv4 multicast
	netip.MustParsePrefix("ff00::/8"),    // IPv6 multicast
	netip.MustParsePrefix("255.255.255.255/32"),
}

// mandatoryNeverBlock are addresses this host must never cut itself off from,
// whatever any configuration says.
//
// The link-local ranges belong here and not in the never-count list. Never-count
// suppresses detection, never-block only forbids the firewall rule: a source in
// fe80::/10 or 169.254.0.0/16 must still be seen scanning, since scanning a
// neighbour by its link-local address is ordinary on IPv6 and one command away
// on IPv4, and that on-link attacker is the one for whom the reported MAC means
// something.
var mandatoryNeverBlock = append(
	append([]netip.Prefix(nil), mandatoryNeverCount...),
	netip.MustParsePrefix("169.254.0.0/16"), // IPv4 link-local
	netip.MustParsePrefix("fe80::/10"),      // IPv6 link-local
)

// infrastructure holds the addresses this host depends on to have a network at
// all: the next hop of every route, and every configured resolver. They are the
// most damaging addresses to get blocked and the easiest to guess (`nmap -D
// <gateway>`). The list is derived, never configured, and refreshed with the
// snapshot because a DHCP renewal or a route change moves it.
type infrastructure struct {
	// gateways and resolvers are what the last successful read observed. They
	// are what the status output reports.
	gateways  []netip.Addr
	resolvers []netip.Addr

	// protected maps every address observed as infrastructure to when it was
	// last observed, and is what the guard consults. A memory with a fading edge
	// rather than a snapshot: during a DHCP renewal, a Wi-Fi change or a VPN
	// transition the default route is withdrawn and reinstalled, and a
	// snapshot taken in between would protect neither the old gateway nor the
	// new one. An address stays protected for infraRetention after it was last
	// seen.
	protected map[netip.Addr]time.Time
}

// infraRetention is how long an address stays protected after it stops being
// observed as infrastructure.
const infraRetention = 5 * time.Minute

// maxProtected bounds the memory above, so a machine with a very large routing
// table cannot make it grow without limit.
const maxProtected = 512

func (i infrastructure) contains(a netip.Addr, now time.Time) bool {
	t, ok := i.protected[a]
	return ok && now.Sub(t) < infraRetention
}

// observe folds a fresh reading into the memory: what was seen now is stamped
// now, and what has not been seen for infraRetention is forgotten.
// haveGateways and haveResolvers say which halves of fresh were read; a half
// that failed stamps and replaces nothing, and does not cost the other half its
// update -- a broken resolv.conf must not unprotect the gateway.
func (i *infrastructure) observe(fresh infrastructure, now time.Time, haveGateways, haveResolvers bool) {
	if i.protected == nil {
		i.protected = map[netip.Addr]time.Time{}
	}
	for a, t := range i.protected {
		if now.Sub(t) >= infraRetention {
			delete(i.protected, a)
		}
	}
	stamp := func(addrs []netip.Addr) {
		for _, a := range addrs {
			if _, known := i.protected[a]; !known && len(i.protected) >= maxProtected {
				continue
			}
			i.protected[a] = now
		}
	}
	if haveGateways {
		stamp(fresh.gateways)
		i.gateways = fresh.gateways
	}
	if haveResolvers {
		stamp(fresh.resolvers)
		i.resolvers = fresh.resolvers
	}
}

// maxResolvers bounds the resolvers retained per file. contains is a linear
// scan, and anything that writes resolv.conf chooses its length; glibc itself
// uses at most three.
const maxResolvers = 64

// maxConfigLine is how long a line these readers accept. bufio.Scanner stops at
// 64 KB, and the `search` line dhclient writes is chosen by the DHCP server, so
// the default limit would give it a way to break the read on demand. A broken
// read is still reported (sc.Err) for files that are genuinely broken.
const maxConfigLine = 1 << 20

// readInfrastructure reads the derived never-block addresses, reporting
// separately whether each kind was read. A source that is missing is not an
// error -- a machine may have no default route -- but a read that started and
// broke off is: it would look like a complete list and protect only what came
// before the break. The two kinds come from different files and fail
// independently, and a failure of one must not discard the other.
func readInfrastructure() (inf infrastructure, gatewayErr, resolverErr error) {
	v4, err4 := readIPv4Gateways()
	v6, err6 := readIPv6Gateways()
	res, errR := readResolvers()
	inf.gateways = append(inf.gateways, v4...)
	inf.gateways = append(inf.gateways, v6...)
	inf.resolvers = res
	return inf, errors.Join(err4, err6), errR
}

// readIPv4Gateways parses /proc/net/route for every non-zero next hop.
//
// Every next hop is taken, not only the default route's: a machine that reaches
// its DNS server or its domain controller through a specific route depends on
// that hop just as much.
func readIPv4Gateways() ([]netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		// A machine with no routing table at all is a legitimate state, and
		// distinguishable from a read that broke off half way.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("portscan: reading /proc/net/route: %w", err)
	}
	defer f.Close()

	var out []netip.Addr
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxConfigLine)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[0] == "Iface" {
			continue
		}
		// Field 2 is the gateway, little-endian hexadecimal.
		v, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		out = append(out, netip.AddrFrom4([4]byte{
			byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
		}))
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("portscan: reading /proc/net/route: %w", err)
	}
	return out, nil
}

// readIPv6Gateways parses /proc/net/ipv6_route for every non-unspecified next
// hop. It is usually link-local, and covered already, but a global next hop is
// just as load-bearing.
func readIPv6Gateways() ([]netip.Addr, error) {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("portscan: reading /proc/net/ipv6_route: %w", err)
	}
	defer f.Close()

	var out []netip.Addr
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxConfigLine)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// dst plen src splen nexthop metric refcnt use flags iface
		if len(fields) < 5 {
			continue
		}
		raw, err := hex.DecodeString(fields[4])
		if err != nil || len(raw) != 16 {
			continue
		}
		a, ok := netip.AddrFromSlice(raw)
		if !ok || a.IsUnspecified() {
			continue
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("portscan: reading /proc/net/ipv6_route: %w", err)
	}
	return out, nil
}

// resolvConfPaths are read in order; all of them, because a systemd-resolved
// machine has a stub in /etc/resolv.conf and the real servers in the run-time
// file, and blocking either breaks name resolution.
var resolvConfPaths = []string{
	"/etc/resolv.conf",
	"/run/systemd/resolve/resolv.conf",
	"/run/resolvconf/resolv.conf",
}

func readResolvers() ([]netip.Addr, error) {
	seen := map[netip.Addr]bool{}
	// Per file, so the budget is shared out rather than spent first-come: the
	// first file, /etc/resolv.conf, is written from what the DHCP server sends, and
	// must not crowd out the resolver listed in the next one.
	perFile := maxResolvers / len(resolvConfPaths)
	if perFile < 1 {
		perFile = 1
	}
	var out []netip.Addr
	var firstErr error
	for _, path := range resolvConfPaths {
		fromThisFile := 0
		f, err := os.Open(path)
		if err != nil {
			// Absence is ordinary: a systemd-resolved machine has only some of
			// these paths. A permission error or a broken mount is not, and
			// silently treating it as "no resolvers" is what leaves the guard
			// looking present and protecting nothing.
			if !os.IsNotExist(err) && firstErr == nil {
				firstErr = fmt.Errorf("portscan: reading %s: %w", path, err)
			}
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxConfigLine)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, "nameserver") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			// A resolver address may carry a zone; strip it, as everywhere
			// else, so the two spellings cannot diverge.
			a, err := netip.ParseAddr(fields[1])
			if err != nil {
				continue
			}
			a = normalizeAddr(a)
			if !seen[a] {
				if fromThisFile >= perFile || len(out) >= maxResolvers {
					continue
				}
				seen[a] = true
				out = append(out, a)
				fromThisFile++
			}
		}
		if err := sc.Err(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("portscan: reading %s: %w", path, err)
		}
		f.Close()
	}
	return out, firstErr
}

// normalizeAddr reduces an address to the single form everything else compares
// against: no IPv4-mapped prefix, no interface zone. netip.Prefix.Contains is
// false for any zoned address, so fe80::1%eth0 would walk through every
// exemption check while nftables, stripping the zone, dropped fe80::1. It is
// applied inside the predicates, not only by callers.
func normalizeAddr(a netip.Addr) netip.Addr {
	return a.Unmap().WithZone("")
}

// Refresh rebuilds the snapshot from the kernel.
func (h *SystemHostInfo) Refresh() error {
	local, onLink, err := readInterfaces()
	if err != nil {
		// Wrapped so the caller can tell this apart from an infrastructure read
		// failing: without the host's own addresses every packet loses its meaning.
		return fmt.Errorf("%w: %w", ErrHostAddresses, err)
	}
	listening, established, socketsOverflowed, socketsErr := readSockets()
	infra, gatewayErr, resolverErr := readInfrastructure()
	infraErr := errors.Join(gatewayErr, resolverErr)
	now := time.Now()

	h.mu.Lock()
	defer h.mu.Unlock()
	h.localAddrs = local
	h.onLink = onLink
	// A socket read that broke off replaces nothing: a partial snapshot would
	// make HasConnection forget live connections and score their return traffic.
	if socketsErr == nil {
		h.listening = listening
		h.established = established
	}
	if infraErr != nil {
		h.infraErr.Store(&infraErr)
	} else {
		h.infraErr.Store(nil)
	}
	// A read that broke off replaces nothing, but only for the half that broke
	// off; the previous list for that half stands and ages out on its own.
	h.infra.observe(infra, now, gatewayErr == nil, resolverErr == nil)
	if socketsErr != nil {
		h.reportError(degraded("the connection tables could not be read in"+
			" full, so the previous snapshot stands: %w", socketsErr))
	}
	if socketsOverflowed {
		// Reported, not silent. This bound being reached means something is
		// holding tens of thousands of connections or TIME_WAIT entries against
		// this host, which is itself worth knowing, and it means return traffic
		// from the connections past the cap is scored as though this host did
		// not know about it.
		h.reportError(degraded("more than %d connections are open or in"+
			" TIME_WAIT; the connection table is capped there, so return traffic from"+
			" the rest is scored as unknown", maxEstablished))
	}
	return infraErr
}

// Infrastructure returns the derived never-block addresses, so the daemon can
// log what it protected and the user can see it.
func (h *SystemHostInfo) Infrastructure() (gateways, resolvers []netip.Addr) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]netip.Addr(nil), h.infra.gateways...),
		append([]netip.Addr(nil), h.infra.resolvers...)
}

// readInterfaces collects this host's unicast addresses and attached prefixes.
func readInterfaces() (map[netip.Addr]bool, []netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	addrs := make(map[netip.Addr]bool, 16)
	prefixes := make([]netip.Prefix, 0, 16)
	for _, ifi := range ifaces {
		list, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range list {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			na, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			na = na.Unmap()
			addrs[na] = true
			ones, _ := ipn.Mask.Size()
			if p, err := na.Prefix(ones); err == nil {
				prefixes = append(prefixes, p)
			}
		}
	}
	return addrs, prefixes, nil
}

// maxEstablished bounds the connection table, whose size a remote peer
// decides: every closed connection leaves a TIME_WAIT line for a minute, and the
// table is rebuilt every ten seconds. Overflowing is safe in the direction
// that matters: a connection missing from the table makes its return traffic
// score at the lowest weight and never count as evidence.
const maxEstablished = 65536

// readSockets is a variable so a test can make the read fail, and show that a
// failed read replaces nothing.
var readSockets = readSocketTables

// readSocketTables reads the listening sockets and established connections.
// A listening socket is recognised as /proc/net/tcp expresses one: a local
// port with no remote peer.
func readSocketTables() (listening map[listenKey]bool, established map[flowKey]bool, overflowed bool, err error) {
	listening = make(map[listenKey]bool, 64)
	established = make(map[flowKey]bool, 256)
	var failures []error

	for _, spec := range []struct {
		files []string
		proto uint8
	}{
		{[]string{"tcp", "tcp6"}, ProtoTCP},
		{[]string{"udp", "udp6"}, ProtoUDP},
	} {
		for _, f := range spec.files {
			entries, perr := netstat.Parse(f)
			if perr != nil {
				// Collected rather than swallowed. Refresh needs to know that a
				// read learned nothing, so it can decline to replace a good
				// snapshot with a partial one, as it does for readInfrastructure.
				failures = append(failures, fmt.Errorf("/proc/net/%s: %w", f, perr))
				continue
			}
			for _, e := range entries {
				if e.DstPort == 0 || e.DstIP == nil || e.DstIP.IsUnspecified() {
					// No peer: a listening socket (TCP) or a bound datagram
					// socket (UDP).
					listening[listenKey{proto: spec.proto, port: uint16(e.SrcPort)}] = true
					continue
				}
				local, lok := netip.AddrFromSlice(e.SrcIP)
				remote, rok := netip.AddrFromSlice(e.DstIP)
				if !lok || !rok {
					continue
				}
				// A socket with a peer is still bound to its local port, and
				// packets to that port are not probes of a closed port.
				listening[listenKey{proto: spec.proto, port: uint16(e.SrcPort)}] = true
				if len(established) >= maxEstablished {
					// Stop adding, and say so once. The listening set keeps
					// being filled: it is the small one, and it is what tells a
					// closed port from an open one, which is the distinction
					// the score actually turns on.
					overflowed = true
					continue
				}
				established[flowKey{
					proto:      spec.proto,
					remote:     remote.Unmap(),
					remotePort: uint16(e.DstPort),
					local:      local.Unmap(),
					localPort:  uint16(e.SrcPort),
				}] = true
			}
		}
	}
	return listening, established, overflowed, errors.Join(failures...)
}

// IsLocalUnicast implements HostInfo.
func (h *SystemHostInfo) IsLocalUnicast(a netip.Addr) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.localAddrs[normalizeAddr(a)]
}

// IsListening implements HostInfo.
func (h *SystemHostInfo) IsListening(proto uint8, port uint16) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.listening[listenKey{proto: proto, port: port}]
}

// HasConnection implements HostInfo. It is the check no network sensor can
// make: look at the socket table instead of guessing from TCP flags.
func (h *SystemHostInfo) HasConnection(p *Probe) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.established[flowKey{
		proto:      p.Proto,
		remote:     normalizeAddr(p.Src),
		remotePort: p.SrcPort,
		local:      normalizeAddr(p.Dst),
		localPort:  p.DstPort,
	}]
}

// IsOnLink implements HostInfo.
func (h *SystemHostInfo) IsOnLink(a netip.Addr) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	a = normalizeAddr(a)
	for _, p := range h.onLink {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsExempt implements HostInfo.
func (h *SystemHostInfo) IsExempt(a netip.Addr) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	a = normalizeAddr(a)
	// Our own addresses are never a scanner. psad reached the same conclusion
	// the hard way (auto_block_ignore_ip, psad:7209-7227).
	if h.localAddrs[a] {
		return true
	}
	for _, p := range h.exempt {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsNeverBlock reports whether addr must never have a firewall rule installed
// against it, whatever any policy or user interface asks.
//
// It is a wider set than IsExempt, and answers a different question. IsExempt
// means "do not count this as a scan", which would be wrong for the gateway: a
// gateway that really scans is worth knowing about. IsNeverBlock means "do not
// cut the host off from this", true of the gateway whether or not the packets
// are genuine. An operator writing NeverBlock: ["192.168.0.0/16"] must not lose
// detection on their own LAN.
func (h *SystemHostInfo) IsNeverBlock(a netip.Addr) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	a = normalizeAddr(a)
	if h.localAddrs[a] {
		return true
	}
	// The addresses this host needs to have a network at all. Derived, never
	// configured: a configuration mistake must not be able to expose them, and
	// they move with the network, so they are refreshed with the snapshot.
	if h.infra.contains(a, time.Now()) {
		return true
	}
	for _, p := range mandatoryNeverBlock {
		if p.Contains(a) {
			return true
		}
	}
	for _, p := range h.exempt {
		if p.Contains(a) {
			return true
		}
	}
	for _, p := range h.neverBlock {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// SetNeverBlock replaces the operator's never-block prefix list. It is additive
// to the derived and mandatory entries, which it can never remove.
func (h *SystemHostInfo) SetNeverBlock(prefixes []netip.Prefix) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.neverBlock = append([]netip.Prefix(nil), prefixes...)
}

// ExemptPrefixes returns the effective never-count list, mandatory entries
// included, for the eBPF maps and for display. Only this list goes to the
// kernel: filtering never-block addresses there would stop the engine seeing
// them at all.
func (h *SystemHostInfo) ExemptPrefixes() []netip.Prefix {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]netip.Prefix, len(h.exempt))
	copy(out, h.exempt)
	return out
}

// LocalAddrs returns this host's unicast addresses.
func (h *SystemHostInfo) LocalAddrs() []netip.Addr {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]netip.Addr, 0, len(h.localAddrs))
	for a := range h.localAddrs {
		out = append(out, a)
	}
	return out
}

var _ HostInfo = (*SystemHostInfo)(nil)
