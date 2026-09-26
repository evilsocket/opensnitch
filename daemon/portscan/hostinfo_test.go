//go:build linux

package portscan

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestHostInfo(t *testing.T, exempt ...netip.Prefix) *SystemHostInfo {
	t.Helper()
	h, err := NewSystemHostInfo(exempt, time.Hour)
	if err != nil {
		t.Fatalf("NewSystemHostInfo: %v", err)
	}
	t.Cleanup(h.Stop)
	return h
}

// ---------------------------------------------------------------------------
// the exemption list -- the guard that stops the host harming itself
// ---------------------------------------------------------------------------

// TestMandatoryExemptionsCannotBeOmitted is the anti-self-harm guarantee.
//
// psad shipped without it and had to add auto_block_ignore_ip() after the fact
// (ChangeLog:1111). These prefixes are therefore not configurable: no
// configuration file, and no message from a user interface, can make the host
// block its own loopback, its link-local range or a multicast group.
func TestMandatoryExemptionsCannotBeOmitted(t *testing.T) {
	// An empty operator list: whatever is exempt below is exempt because the
	// code insists on it.
	h := newTestHostInfo(t)

	// Never counted: traffic that cannot be a scan of this host.
	for _, tc := range []struct {
		addr string
		why  string
	}{
		{"127.0.0.1", "IPv4 loopback"},
		{"127.4.5.6", "the whole 127/8 range"},
		{"::1", "IPv6 loopback"},
		{"224.0.0.251", "IPv4 multicast (mDNS)"},
		{"ff02::fb", "IPv6 multicast (mDNS)"},
		{"255.255.255.255", "the limited broadcast address"},
	} {
		if !h.IsExempt(netip.MustParseAddr(tc.addr)) {
			t.Errorf("%s (%s) must never be counted", tc.addr, tc.why)
		}
		if !h.IsNeverBlock(netip.MustParseAddr(tc.addr)) {
			t.Errorf("%s (%s) must never be blocked either", tc.addr, tc.why)
		}
	}

	// Never BLOCKED, but very much counted.
	//
	// With the link-local ranges in the never-count list, their packets
	// would be discarded before scoring: an attacker on the link -- the one
	// the threat model singles out, and the only one whose source MAC this
	// feature can meaningfully report -- would be invisible at no cost, since
	// fe80:: is simply what every IPv6 node on a link already has. Measured
	// that way, 1023 probes from fe80::dead:beef scored zero and reported
	// nothing.
	for _, tc := range []struct {
		addr string
		why  string
	}{
		{"169.254.10.20", "IPv4 link-local"},
		{"fe80::1234", "IPv6 link-local"},
	} {
		a := netip.MustParseAddr(tc.addr)
		if h.IsExempt(a) {
			t.Errorf("%s (%s) is exempt from COUNTING: a scan from the link is invisible",
				tc.addr, tc.why)
		}
		if !h.IsNeverBlock(a) {
			t.Errorf("%s (%s) must still never be blocked: the host needs its own link",
				tc.addr, tc.why)
		}
	}
}

// TestSetExemptKeepsTheMandatoryEntries: replacing the operator list must not
// be a way to drop the mandatory ones.
func TestSetExemptKeepsTheMandatoryEntries(t *testing.T) {
	h := newTestHostInfo(t, netip.MustParsePrefix(exemptPrefix))

	if !h.IsExempt(exemptSrc) {
		t.Fatalf("the operator prefix %s is not in force", exemptPrefix)
	}

	h.SetExempt(nil)

	if h.IsExempt(exemptSrc) {
		t.Fatalf("the operator prefix survived being replaced by an empty list")
	}
	if !h.IsExempt(netip.MustParseAddr("127.0.0.1")) {
		t.Fatalf("replacing the operator list dropped the mandatory entries")
	}
}

func TestOrdinaryAddressIsNotExempt(t *testing.T) {
	h := newTestHostInfo(t)
	for _, a := range []string{"192.0.2.66", "203.0.113.7", "2001:db8::66"} {
		if h.IsExempt(netip.MustParseAddr(a)) {
			t.Errorf("%s must not be exempt", a)
		}
	}
}

// TestOwnAddressesAreExempt is the check that keeps a host from blocking
// itself. It is derived from the live interface list rather than configured, so
// it holds on any machine.
func TestOwnAddressesAreExempt(t *testing.T) {
	h := newTestHostInfo(t)

	own := h.LocalAddrs()
	if len(own) == 0 {
		t.Fatalf("no local address was found; the host view is empty")
	}
	for _, a := range own {
		if !h.IsExempt(a) {
			t.Errorf("this host's own address %s is not exempt", a)
		}
		if !h.IsLocalUnicast(a) {
			t.Errorf("%s is in LocalAddrs but IsLocalUnicast says no", a)
		}
	}
	if !h.IsLocalUnicast(netip.MustParseAddr("127.0.0.1")) {
		t.Fatalf("127.0.0.1 must be recognised as one of this host's addresses")
	}
}

// TestExemptionAcceptsTheMappedForm: an address arriving as ::ffff:127.0.0.1
// must be recognised as the same address, or the guard could be walked around
// by presenting the other form.
func TestExemptionAcceptsTheMappedForm(t *testing.T) {
	h := newTestHostInfo(t)

	v4 := netip.MustParseAddr("127.0.0.1")
	mapped := netip.AddrFrom16(v4.As16())
	if !mapped.Is4In6() {
		t.Fatalf("the test built %v, which is not a mapped address", mapped)
	}
	if !h.IsExempt(mapped) {
		t.Fatalf("%v must be exempt: it is 127.0.0.1", mapped)
	}
	if !h.IsLocalUnicast(mapped) {
		t.Fatalf("%v must be recognised as local", mapped)
	}
}

func TestExemptPrefixesIsACopy(t *testing.T) {
	h := newTestHostInfo(t)

	list := h.ExemptPrefixes()
	if len(list) == 0 {
		t.Fatalf("the mandatory list is empty")
	}
	list[0] = netip.MustParsePrefix("203.0.113.0/24")

	if h.IsExempt(netip.MustParseAddr("203.0.113.1")) {
		t.Fatalf("mutating the returned slice changed the live exemption list")
	}
	if !h.IsExempt(netip.MustParseAddr("127.0.0.1")) {
		t.Fatalf("mutating the returned slice dropped a mandatory entry")
	}
}

// ---------------------------------------------------------------------------
// on-link determination, which decides whether a MAC may be attributed
// ---------------------------------------------------------------------------

func TestIsOnLink(t *testing.T) {
	h := newTestHostInfo(t)

	// Loopback is attached to this host by definition, on every machine.
	if !h.IsOnLink(netip.MustParseAddr("127.0.0.1")) {
		t.Fatalf("127.0.0.1 must be on-link")
	}
	// A documentation range is not routed here.
	if h.IsOnLink(netip.MustParseAddr("203.0.113.7")) {
		t.Fatalf("203.0.113.7 must not be on-link")
	}
	if h.IsOnLink(netip.MustParseAddr("2001:db8::66")) {
		t.Fatalf("2001:db8::66 must not be on-link")
	}
}

// ---------------------------------------------------------------------------
// the socket view, checked against the real kernel
// ---------------------------------------------------------------------------

// TestListeningSocketIsSeen opens a real listener and asserts the host view
// finds it after a refresh.
//
// This is the check no network sensor can make, and the reason a host firewall
// can weigh a SYN to a closed port differently from a SYN to a running service.
// Asserting it against a hand-built map would only prove the map works.
func TestListeningSocketIsSeen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	h := newTestHostInfo(t)
	if !h.IsListening(ProtoTCP, port) {
		t.Fatalf("the listening socket on port %d was not found in /proc", port)
	}
	if h.IsListening(ProtoUDP, port) {
		t.Fatalf("a TCP listener must not be reported as a UDP one")
	}
}

func TestUDPBoundSocketIsSeen(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket: %v", err)
	}
	defer pc.Close()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)

	h := newTestHostInfo(t)
	if !h.IsListening(ProtoUDP, port) {
		t.Fatalf("the bound UDP socket on port %d was not found in /proc", port)
	}
}

// TestEstablishedConnectionIsRecognised checks the orientation of the flow key,
// which is the subtle part: HasConnection is asked about an *inbound* packet,
// so the probe's source is the connection's remote end.
//
// Getting this backwards would make every established connection look like an
// unsolicited probe -- and every genuine probe look like return traffic.
func TestEstablishedConnectionIsRecognised(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer client.Close()

	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(2 * time.Second):
		t.Fatalf("the connection was never accepted")
	}

	local := client.RemoteAddr().(*net.TCPAddr) // the server end
	remote := client.LocalAddr().(*net.TCPAddr) // the client end
	serverAddr := netip.MustParseAddr("127.0.0.1")

	h := newTestHostInfo(t)

	// A packet arriving at the server from the client: it belongs to a
	// connection this host knows about.
	inbound := &Probe{
		Proto:   ProtoTCP,
		Src:     serverAddr,
		SrcPort: uint16(remote.Port),
		Dst:     serverAddr,
		DstPort: uint16(local.Port),
	}
	if !h.HasConnection(inbound) {
		t.Fatalf("the established connection %d -> %d was not recognised", remote.Port, local.Port)
	}

	// The same ports against a different peer address is a different flow.
	other := *inbound
	other.Src = netip.MustParseAddr("192.0.2.66")
	if h.HasConnection(&other) {
		t.Fatalf("a flow from a different peer must not match")
	}

	// A port nobody is talking to.
	none := *inbound
	none.SrcPort = 1
	if h.HasConnection(&none) {
		t.Fatalf("an unrelated flow must not match")
	}

	// UDP is a different protocol space.
	udp := *inbound
	udp.Proto = ProtoUDP
	if h.HasConnection(&udp) {
		t.Fatalf("a TCP flow must not match a UDP probe")
	}
}

// TestEveryEstablishedFlowIsAlsoListening pins the invariant readSockets
// deliberately establishes: a socket with a peer is still bound to its local
// port, so packets to that port are not probes of a closed port.
//
// It runs over whatever this machine really has open.
func TestEveryEstablishedFlowIsAlsoListening(t *testing.T) {
	listening, established, _, _ := readSockets()
	if listening == nil || established == nil {
		t.Fatalf("readSockets returned nil maps")
	}
	for f := range established {
		if !listening[listenKey{proto: f.proto, port: f.localPort}] {
			t.Fatalf("flow %v has a local port that is not marked bound", f)
		}
	}
}

// TestReadInterfacesAgreesWithTheStandardLibrary cross-checks the snapshot
// against net.Interfaces directly, so a parsing slip cannot pass unnoticed.
func TestReadInterfacesAgreesWithTheStandardLibrary(t *testing.T) {
	addrs, prefixes, err := readInterfaces()
	if err != nil {
		t.Fatalf("readInterfaces: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatalf("no address was collected")
	}
	if len(prefixes) == 0 {
		t.Fatalf("no prefix was collected")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	seen := 0
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
			seen++
			if !addrs[na.Unmap()] {
				t.Errorf("%s is on %s but missing from the snapshot", na, ifi.Name)
			}
		}
	}
	if seen == 0 {
		t.Fatalf("the standard library reported no interface address either")
	}

	// Every collected address must be inside at least one collected prefix.
	for a := range addrs {
		found := false
		for _, p := range prefixes {
			if p.Contains(a) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("address %s is in no collected prefix", a)
		}
	}
}

// ---------------------------------------------------------------------------
// lifecycle and concurrency
// ---------------------------------------------------------------------------

func TestNewSystemHostInfoDefaultsTheRefreshInterval(t *testing.T) {
	h, err := NewSystemHostInfo(nil, 0)
	if err != nil {
		t.Fatalf("NewSystemHostInfo: %v", err)
	}
	defer h.Stop()
	if h.refreshEvery != 10*time.Second {
		t.Fatalf("refreshEvery = %v, want the 10s default", h.refreshEvery)
	}
}

// TestFirstRefreshIsSynchronous: an engine fed from an empty snapshot would see
// every packet as aimed at an address that is not ours, and count nothing.
func TestFirstRefreshIsSynchronous(t *testing.T) {
	h, err := NewSystemHostInfo(nil, time.Hour)
	if err != nil {
		t.Fatalf("NewSystemHostInfo: %v", err)
	}
	defer h.Stop()

	// Start was never called, so only the constructor's own refresh can have
	// populated this.
	if len(h.LocalAddrs()) == 0 {
		t.Fatalf("the snapshot is empty before Start; the first refresh did not run")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	h, err := NewSystemHostInfo(nil, time.Hour)
	if err != nil {
		t.Fatalf("NewSystemHostInfo: %v", err)
	}
	h.Start()
	h.Stop()
	h.Stop() // must not panic on an already-closed channel
}

// TestHostInfoConcurrentReadsAndRefresh runs the packet-path readers against a
// refresh, which is exactly the production pattern: the refresh loop rebuilds
// the snapshot while probes are being classified.
func TestHostInfoConcurrentReadsAndRefresh(t *testing.T) {
	h := newTestHostInfo(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if err := h.Refresh(); err != nil {
					t.Errorf("Refresh: %v", err)
					return
				}
			}
		}
	}()

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			p := &Probe{
				Proto: ProtoTCP, SrcPort: 1234, DstPort: uint16(1000 + w),
				Src: netip.MustParseAddr("192.0.2.66"),
				Dst: netip.MustParseAddr("127.0.0.1"),
			}
			for i := 0; i < 2000; i++ {
				_ = h.IsExempt(p.Src)
				_ = h.IsLocalUnicast(p.Dst)
				_ = h.IsListening(ProtoTCP, uint16(i))
				_ = h.HasConnection(p)
				_ = h.IsOnLink(p.Dst)
				_ = h.ExemptPrefixes()
			}
		}(w)
	}

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				h.SetExempt([]netip.Prefix{netip.MustParsePrefix(exemptPrefix)})
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Whatever the interleaving, the mandatory entries are still in force.
	if !h.IsExempt(netip.MustParseAddr("127.0.0.1")) {
		t.Fatalf("the mandatory exemptions did not survive concurrent updates")
	}
}

// TestHostInfoSatisfiesTheEngineInterface is a compile-time-ish guarantee made
// explicit, and a smoke test that the engine can actually be driven by the real
// host view rather than only by the test double.
func TestHostInfoSatisfiesTheEngineInterface(t *testing.T) {
	h := newTestHostInfo(t)

	var iface HostInfo = h
	cfg := testConfig()
	e, err := NewEngine(cfg, iface, 0)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	local := netip.MustParseAddr("127.0.0.1")
	var ev *ScanEvent
	for i := 0; i < 60 && ev == nil; i++ {
		ev = e.Process(flagProbe(uint64(i)*ms, attacker, local, uint16(20000+i), TCPFin))
	}
	if ev == nil {
		t.Fatalf("a 60-port FIN scan against the real host view produced no event")
	}
	if ev.Src != attacker {
		t.Fatalf("event source = %s, want %s", ev.Src, attacker)
	}

	// A scan whose source is one of our own addresses must be filtered by the
	// exemption, not reported.
	e2, err := NewEngine(cfg, iface, 0)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	own := h.LocalAddrs()[0]
	if own.IsLoopback() && len(h.LocalAddrs()) > 1 {
		own = h.LocalAddrs()[1]
	}
	for i := 0; i < 60; i++ {
		if got := e2.Process(flagProbe(uint64(i)*ms, own, local, uint16(20000+i), TCPFin)); got != nil {
			t.Fatalf("a scan attributed to our own address %s was reported", own)
		}
	}
}

// TestListenKeyAndFlowKeyAreComparable documents why these types have no
// pointers or slices: they are map keys on the packet path, so they must be
// comparable and allocation-free.
func TestListenKeyAndFlowKeyAreComparable(t *testing.T) {
	a := flowKey{proto: ProtoTCP, remote: attacker, remotePort: 1, local: victim, localPort: 2}
	b := flowKey{proto: ProtoTCP, remote: attacker, remotePort: 1, local: victim, localPort: 2}
	if a != b {
		t.Fatalf("identical flow keys compare unequal")
	}
	m := map[flowKey]bool{a: true}
	if !m[b] {
		t.Fatalf("an identical flow key does not hash to the same bucket")
	}

	// Every field must take part in the identity, or two different flows would
	// collide and one would be mistaken for the other.
	variants := []flowKey{
		{proto: ProtoUDP, remote: attacker, remotePort: 1, local: victim, localPort: 2},
		{proto: ProtoTCP, remote: victim, remotePort: 1, local: victim, localPort: 2},
		{proto: ProtoTCP, remote: attacker, remotePort: 9, local: victim, localPort: 2},
		{proto: ProtoTCP, remote: attacker, remotePort: 1, local: attacker, localPort: 2},
		{proto: ProtoTCP, remote: attacker, remotePort: 1, local: victim, localPort: 9},
	}
	for i, v := range variants {
		if v == a {
			t.Errorf("variant %d compares equal to the reference key", i)
		}
		if m[v] {
			t.Errorf("variant %d collides with the reference key", i)
		}
	}

	if (listenKey{proto: ProtoTCP, port: 80}) == (listenKey{proto: ProtoUDP, port: 80}) {
		t.Fatalf("the protocol must be part of the listening key")
	}
}

// ---------------------------------------------------------------------------
// regression tests for the security properties
// ---------------------------------------------------------------------------

// TestZonedAddressCannotBypassTheExemptions guards against a bypass of the one
// guard this feature says is not configurable.
//
// netip.Prefix.Contains returns false for any address carrying an interface
// zone -- documented behaviour, "because Prefixes strip zones" -- and a map
// keyed by unzoned addresses never matches one either. Left zoned,
// fe80::1%eth0 would walk through every check, and nftables would then strip
// the zone when installing the element, applying the drop to fe80::1: the
// address that had just been refused. fe80::1 is the commonest IPv6 default
// gateway there is.
func TestZonedAddressCannotBypassTheExemptions(t *testing.T) {
	h := newTestHostInfo(t, netip.MustParsePrefix(exemptPrefix))
	h.SetNeverBlock([]netip.Prefix{netip.MustParsePrefix(neverBlockPrefix)})

	for _, tc := range []struct {
		zoned, plain string
	}{
		{"::1%lo", "::1"},
		{"fe80::1%eth0", "fe80::1"},
		{"ff02::1%eth0", "ff02::1"},
		{"fe80::1%1", "fe80::1"},
		{"fe80::1%does-not-exist", "fe80::1"},
	} {
		zoned := netip.MustParseAddr(tc.zoned)
		plain := netip.MustParseAddr(tc.plain)

		if h.IsExempt(plain) != h.IsExempt(zoned) {
			t.Errorf("IsExempt(%s) = %v but IsExempt(%s) = %v",
				tc.plain, h.IsExempt(plain), tc.zoned, h.IsExempt(zoned))
		}
		if h.IsNeverBlock(plain) != h.IsNeverBlock(zoned) {
			t.Errorf("IsNeverBlock(%s) = %v but IsNeverBlock(%s) = %v",
				tc.plain, h.IsNeverBlock(plain), tc.zoned, h.IsNeverBlock(zoned))
		}
		if !h.IsNeverBlock(zoned) {
			t.Errorf("%s must never be blocked", tc.zoned)
		}
	}

	// And the block manager, which is the thing that would install the rule.
	fb := newFakeBlocker()
	mgr, _ := newTestBlockManager(t, fb, testBlockConfig(), h.IsNeverBlock)
	for _, s := range []string{"::1%lo", "fe80::1%eth0", "ff02::1%eth0"} {
		if err := mgr.Block(netip.MustParseAddr(s), "scan"); err == nil {
			t.Errorf("Block(%s) was accepted despite the mandatory list", s)
		}
	}
	if fb.count() != 0 {
		t.Fatalf("a zoned exempt address reached the firewall backend")
	}
}

// TestInfrastructureIsNeverBlockable: the gateway and the resolvers were
// documented as "automatically derived" members of the never-block list and
// were not derived at all. nmap -sS -D <gateway> <victim> then cut the victim
// off from its own gateway for four hours.
func TestInfrastructureIsNeverBlockable(t *testing.T) {
	h := newTestHostInfo(t)

	gateways, resolvers := h.Infrastructure()
	t.Logf("derived from this machine: gateways=%v resolvers=%v", gateways, resolvers)

	if len(gateways) == 0 && len(resolvers) == 0 {
		t.Skip("this machine has no default route and no resolver configured")
	}
	for _, a := range append(append([]netip.Addr(nil), gateways...), resolvers...) {
		if !h.IsNeverBlock(a) {
			t.Errorf("%s is infrastructure this host depends on but is blockable", a)
		}
		// It must still be COUNTED: a gateway that really is scanning the host
		// is worth knowing about, and silencing it would be a blind spot an
		// attacker on the gateway could hide in.
		if h.IsExempt(a) && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			t.Errorf("%s is exempt from detection; only blocking should be forbidden", a)
		}
	}
}

// TestOverlongLineInResolvConfIsReportedNotSwallowed: a read that breaks off
// must not be mistaken for a file that ended.
//
// bufio.Scanner stops at ErrTooLong on any line over 64KB. If the error were
// never read, the loop would end normally and the rest of the file would be
// silently ignored. Measured that way: /etc/resolv.conf with a 200KB first
// line followed by `nameserver 9.9.9.9` yielded a resolver list without
// 9.9.9.9 -- and the long line dhclient writes is `search`, which comes first.
// No resolver protected, no trace. readInfrastructure promises that a read
// that broke off is an error; this holds it to that.
func TestOverlongLineInResolvConfIsReportedNotSwallowed(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/resolv.conf"
	// A line past bufio.Scanner's 64KB limit, then a real nameserver after it.
	long := "search " + strings.Repeat("a.very.long.domain.example. ", 8000) + "\n"
	body := long + "nameserver 9.9.9.9\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	saved := resolvConfPaths
	resolvConfPaths = []string{path}
	t.Cleanup(func() { resolvConfPaths = saved })

	// A 200KB line is read in full now: the 64KB default was reachable by
	// anything that writes resolv.conf, including a DHCP server choosing the
	// length of the search list, and a failure an attacker can cause on demand
	// is a way to switch the guard off.
	got, err := readResolvers()
	if err != nil {
		t.Fatalf("a 200KB line broke the read: %v", err)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("9.9.9.9") {
		t.Fatalf("resolvers = %v, want [9.9.9.9]: the nameserver line after the long"+
			" one was not read", got)
	}

	// Past the accepted length the read does break, and that must be REPORTED
	// rather than look like a file that ended. bufio.Scanner stops at ErrTooLong;
	// if that error were discarded, the rest of the file would be silently
	// ignored -- with the long line first, no resolver would be protected.
	huge := "search " + strings.Repeat("a.very.long.domain.example. ", maxConfigLine/8) + "\n"
	if err := os.WriteFile(path, []byte(huge+"nameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = readResolvers()
	if err == nil {
		t.Fatal("a read that stopped at ErrTooLong reported success; the guard looks" +
			" present and protects nothing")
	}
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("err = %v, want it to wrap bufio.ErrTooLong", err)
	}
	t.Logf("resolvers recovered before the break: %v (error: %v)", got, err)

	// And the failure reaches the caller without killing detection: refusing to
	// start would hand whoever wrote that line a way to switch the feature off.
	h, err := NewSystemHostInfo(nil, time.Hour)
	if err != nil {
		t.Fatalf("NewSystemHostInfo refused to start over a resolver read: %v", err)
	}
	t.Cleanup(h.Stop)
	if h.InfraError() == nil {
		t.Fatal("InfraError is nil; the incomplete never-block list is invisible")
	}
}

// TestFailedInfrastructureReadDoesNotReplaceTheList: what a broken read learned
// is nothing, so it must not overwrite what a working one learned.
func TestFailedInfrastructureReadDoesNotReplaceTheList(t *testing.T) {
	h := newTestHostInfo(t)
	gw := netip.MustParseAddr("192.0.2.254")

	h.mu.Lock()
	h.infra.observe(infrastructure{gateways: []netip.Addr{gw}}, time.Now(), true, true)
	h.mu.Unlock()
	if !h.IsNeverBlock(gw) {
		t.Fatal("the seeded gateway is not protected")
	}

	dir := t.TempDir()
	path := dir + "/resolv.conf"
	if err := os.WriteFile(path,
		[]byte("search "+strings.Repeat("x.example. ", maxConfigLine/8)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := resolvConfPaths
	resolvConfPaths = []string{path}
	t.Cleanup(func() { resolvConfPaths = saved })

	if err := h.Refresh(); err == nil {
		t.Fatal("Refresh hid the failed read")
	}
	if !h.IsNeverBlock(gw) {
		t.Fatal("a failed read dropped the protection a successful one had established")
	}
}

// TestGatewayStaysProtectedAcrossADHCPRenewal: a refresh that lands while the
// default route is withdrawn must not leave the gateway unprotected.
//
// readIPv4Gateways sees the next hops present at that instant. During a DHCP
// renewal, a Wi-Fi change, a VPN going up or down, or `dhclient -r`, the default
// route is removed and reinstalled; a refresh in between produced an EMPTY
// gateway list, so for up to a full refresh interval neither the old gateway nor
// the new one was on the never-block list. Nine forged SYN packets in that
// window score the gateway past the threshold, and under Block.Policy "auto"
// that cuts the host off its own network for the block duration -- four hours by
// default, with nothing revisiting the decision.
func TestGatewayStaysProtectedAcrossADHCPRenewal(t *testing.T) {
	gw := netip.MustParseAddr("192.0.2.254")
	var infra infrastructure

	t0 := time.Now()
	infra.observe(infrastructure{gateways: []netip.Addr{gw}}, t0, true, true)
	if !infra.contains(gw, t0) {
		t.Fatal("the gateway is not protected right after being observed")
	}

	// The renewal: the route is gone, so the reading is empty.
	t1 := t0.Add(10 * time.Second)
	infra.observe(infrastructure{}, t1, true, true)
	if !infra.contains(gw, t1) {
		t.Fatal("the gateway lost its protection the moment its route was withdrawn;" +
			" nine forged packets in that window cut the host off its own network")
	}

	// It comes back, and stays protected.
	t2 := t1.Add(5 * time.Second)
	infra.observe(infrastructure{gateways: []netip.Addr{gw}}, t2, true, true)
	if !infra.contains(gw, t2) {
		t.Fatal("the gateway is not protected after the route came back")
	}

	// An address that really has gone is eventually forgotten, or the list would
	// only ever grow and a machine that changes networks would carry its old
	// gateways for ever.
	t3 := t2.Add(infraRetention + time.Second)
	infra.observe(infrastructure{}, t3, true, true)
	if infra.contains(gw, t3) {
		t.Errorf("a gateway absent for more than %v is still protected", infraRetention)
	}
}

// TestProtectedInfrastructureIsBounded: the memory must not be a way to make the
// daemon hold an arbitrary number of addresses.
func TestProtectedInfrastructureIsBounded(t *testing.T) {
	var infra infrastructure
	now := time.Now()
	var many []netip.Addr
	for i := 0; i < maxProtected*4; i++ {
		many = append(many, netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}))
	}
	infra.observe(infrastructure{gateways: many}, now, true, true)
	if got := len(infra.protected); got > maxProtected {
		t.Errorf("protected holds %d addresses, cap is %d", got, maxProtected)
	}
}

// TestBlockIsReleasedWhenTheAddressBecomesExempt: exemption is checked once, at
// install time, against a snapshot up to a refresh interval old. Without a
// later release, a gateway blocked during the window above would stay blocked
// for the whole duration.
func TestBlockIsReleasedWhenTheAddressBecomesExempt(t *testing.T) {
	gw := netip.MustParseAddr("192.0.2.254")
	exempt := false
	b := newFakeBlocker()
	m, err := NewBlockManager(b, BlockConfig{Duration: time.Hour, MaxBlockedSources: 8},
		func(a netip.Addr) bool { return exempt && a == gw })
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Block(gw, "scan"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !m.IsBlocked(gw) {
		t.Fatal("the block was not installed")
	}

	// The snapshot catches up: this address is the host's gateway after all.
	exempt = true
	if n := m.ExpireDue(); n != 1 {
		t.Fatalf("ExpireDue released %d blocks, want 1", n)
	}
	if m.IsBlocked(gw) {
		t.Fatal("the host is still cut off from its own gateway after the snapshot" +
			" said the address was infrastructure")
	}
	if b.isActive(gw) {
		t.Fatal("the kernel still holds the block")
	}
}

// TestNeverBlockDoesNotSuppressDetection pins the split between the two lists.
//
// The two lists answer different questions. An operator writing
// NeverBlock: ["192.168.0.0/16"] means "never cut me off from my own LAN";
// if that also stopped counting, they would silently lose all detection on
// that LAN, which is where an internal attacker scans from.
func TestNeverBlockDoesNotSuppressDetection(t *testing.T) {
	h := newTestHostInfo(t, netip.MustParsePrefix(exemptPrefix))
	h.SetNeverBlock([]netip.Prefix{netip.MustParsePrefix(neverBlockPrefix)})

	if h.IsExempt(neverBlockSrc) {
		t.Errorf("%s is on the never-block list; that must not stop it being counted", neverBlockSrc)
	}
	if !h.IsNeverBlock(neverBlockSrc) {
		t.Errorf("%s is on the never-block list and must not be blockable", neverBlockSrc)
	}

	// The never-count list does both, as its name says.
	if !h.IsExempt(exemptSrc) {
		t.Errorf("%s is on the never-count list and must not be counted", exemptSrc)
	}
	if !h.IsNeverBlock(exemptSrc) {
		t.Errorf("%s is not counted, so it can never be blocked either", exemptSrc)
	}
}

// TestExemptPrefixesExcludesTheNeverBlockList: only the never-count list may go
// to the kernel. Filtering never-block addresses there would stop the engine
// from ever seeing them, reintroducing the conflation from the other side.
func TestExemptPrefixesExcludesTheNeverBlockList(t *testing.T) {
	h := newTestHostInfo(t, netip.MustParsePrefix(exemptPrefix))
	h.SetNeverBlock([]netip.Prefix{netip.MustParsePrefix(neverBlockPrefix)})

	for _, p := range h.ExemptPrefixes() {
		if p.String() == neverBlockPrefix {
			t.Fatalf("the never-block prefix %s is pushed to the kernel filter", p)
		}
	}
}

// TestPartialInfrastructureReadKeepsWhatWasRead pins that a failure reading one
// kind of infrastructure does not un-protect the other.
//
// The two come from different files and fail independently, but their errors
// were joined into one and the caller skipped the whole update on any error. A
// resolv.conf that could not be read therefore discarded gateways that
// /proc/net/route had just returned perfectly well, and after infraRetention --
// five minutes, thirty refreshes -- the default gateway stopped being protected
// and became blockable. Nine forged SYN packets then cut the host off its own
// network, which is exactly what the never-block list exists to prevent, caused
// by a file this feature does not need at all.
func TestPartialInfrastructureReadKeepsWhatWasRead(t *testing.T) {
	gw := netip.MustParseAddr("192.0.2.254")
	res := netip.MustParseAddr("192.0.2.53")

	var infra infrastructure
	t0 := time.Now()
	infra.observe(infrastructure{
		gateways:  []netip.Addr{gw},
		resolvers: []netip.Addr{res},
	}, t0, true, true)

	// Resolver reads now fail; gateways still read fine. Simulate thirty
	// refreshes, well past infraRetention.
	at := t0
	for i := 0; i < 30; i++ {
		at = at.Add(10 * time.Second)
		infra.observe(infrastructure{gateways: []netip.Addr{gw}}, at, true, false)
	}

	if !infra.contains(gw, at) {
		t.Fatal("the default gateway stopped being protected because resolv.conf" +
			" could not be read; nine forged packets now cut the host off its network")
	}
	// The resolver, which really was not re-read, ages out -- that half learned
	// nothing, so it asserts nothing.
	if infra.contains(res, at) {
		t.Error("a resolver that has not been observed for longer than the retention" +
			" is still protected")
	}
}

// TestABrokenSocketReadKeepsThePreviousSnapshot: a read of the connection
// tables that broke off learned nothing, so it must replace nothing. Replaced,
// HasConnection forgot live connections and their return traffic was scored as
// unsolicited. The rule is tested for the infrastructure lists elsewhere; it had
// once been applied there and forgotten here.
func TestABrokenSocketReadKeepsThePreviousSnapshot(t *testing.T) {
	flow := flowKey{
		proto:      ProtoTCP,
		remote:     netip.MustParseAddr("198.51.100.20"),
		remotePort: 443,
		local:      netip.MustParseAddr("192.0.2.1"),
		localPort:  40000,
	}
	probe := &Probe{Proto: ProtoTCP, Src: flow.remote, SrcPort: flow.remotePort,
		Dst: flow.local, DstPort: flow.localPort}

	orig := readSockets
	t.Cleanup(func() { readSockets = orig })
	readSockets = func() (map[listenKey]bool, map[flowKey]bool, bool, error) {
		return map[listenKey]bool{}, map[flowKey]bool{flow: true}, false, nil
	}
	h := newTestHostInfo(t)
	var reported []error
	h.SetOnError(func(err error) { reported = append(reported, err) })
	if !h.HasConnection(probe) {
		t.Fatal("the connection was not recorded; the test does not exercise its case")
	}

	readSockets = func() (map[listenKey]bool, map[flowKey]bool, bool, error) {
		return map[listenKey]bool{}, map[flowKey]bool{}, false, errors.New("netlink: message truncated")
	}
	_ = h.Refresh()
	if !h.HasConnection(probe) {
		t.Fatal("a socket read that failed replaced the snapshot: a live connection" +
			" was forgotten, and its return traffic would be scored")
	}
	if len(reported) == 0 {
		t.Error("the failed read was not reported")
	}
}

// TestOwnAddressIsNeverBlock: this host's addresses are never blockable on
// their own account, not only because a mandatory prefix happens to cover them.
func TestOwnAddressIsNeverBlock(t *testing.T) {
	h := newTestHostInfo(t)
	own := netip.MustParseAddr("203.0.113.7")
	h.mu.Lock()
	h.localAddrs = map[netip.Addr]bool{own: true}
	h.exempt = nil
	h.mu.Unlock()
	if !h.IsNeverBlock(own) {
		t.Fatal("this host's own address is blockable")
	}
}
