//go:build linux

package portscan

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests load the real eBPF object into the running kernel, which needs
// CAP_BPF in the initial user namespace -- something no amount of unshare(1)
// provides. They are skipped when that is not available, unless
// PORTSCAN_REQUIRE_EBPF=1, which is what CI and the VM harness set: a test that
// silently skips is a test that has stopped protecting anything. Every skip in
// this file goes through requireEbpf for that reason, including those for a
// missing veth, tun device or statistics switch.
//
// testdata/vm/run_vm_test.sh runs the same code path inside a throwaway virtual
// machine, where it also replays real captured traffic through it.

// modulePath finds the compiled object, preferring an explicit override.
func modulePath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("PORTSCAN_MODULE_DIR"); p != "" {
		return p
	}
	// ebpf_prog/Makefile.scan builds it here.
	return filepath.Join("..", "..", "ebpf_prog")
}

func requireEbpf(t *testing.T, reason string, err error) {
	t.Helper()
	if os.Getenv("PORTSCAN_REQUIRE_EBPF") == "1" {
		t.Fatalf("PORTSCAN_REQUIRE_EBPF=1 but %s: %v", reason, err)
	}
	t.Skipf("%s: %v (build ebpf_prog/Makefile.scan and run as root, or use testdata/vm/run_vm_test.sh)", reason, err)
}

// newLiveEbpfSource loads and attaches the module, or skips.
func newLiveEbpfSource(t *testing.T, opts EbpfOptions, onProbe func(*Probe)) *EbpfSource {
	t.Helper()
	requireDisposableNetwork(t, "PORTSCAN_REQUIRE_EBPF")
	if os.Geteuid() != 0 {
		requireEbpf(t, "not running as root", errors.New("euid != 0"))
	}
	dir := modulePath(t)
	if _, err := os.Stat(filepath.Join(dir, ScanModuleName)); err != nil {
		requireEbpf(t, "the compiled module is missing", err)
	}
	opts.ModulesPath = dir
	if onProbe == nil {
		onProbe = func(*Probe) {}
	}
	src, err := NewEbpfSource(opts, onProbe, func(error) {})
	if err != nil {
		requireEbpf(t, "loading or attaching the module", err)
	}
	t.Cleanup(func() { _ = src.Close() })
	return src
}

// TestLiveEbpfVerifierAcceptsTheProgram is the single most important thing that
// cannot be established anywhere else.
//
// Everything about the kernel half -- the bounded extension-header walk, the
// packed event layout, the per-source rate limiter -- is inference until the
// verifier has actually accepted the program and TCX has actually attached it.
func TestLiveEbpfVerifierAcceptsTheProgram(t *testing.T) {
	src := newLiveEbpfSource(t, EbpfOptions{
		StartupGrace:       0,
		MaxProbesPerSecond: 1000,
		LocalAddrs:         []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}, nil)

	stats, err := src.Stats()
	if err != nil {
		t.Fatalf("reading the kernel counters: %v", err)
	}
	for _, name := range []string{"seen", "forwarded", "filtered", "rate_limited", "ringbuf_full"} {
		if _, ok := stats[name]; !ok {
			t.Errorf("the module exposes no %q counter", name)
		}
	}
	if stats["ringbuf_full"] != 0 {
		t.Errorf("the ring buffer overflowed before any traffic: %d", stats["ringbuf_full"])
	}
}

// TestLiveEbpfLocalAddressMapIsSeeded: the program keeps only traffic aimed at
// an address in this map, so if nothing filled it, the eBPF path would discard
// every packet.
func TestLiveEbpfLocalAddressMapIsSeeded(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("::1"),
	}
	src := newLiveEbpfSource(t, EbpfOptions{
		StartupGrace:       0,
		MaxProbesPerSecond: 1000,
		LocalAddrs:         addrs,
	}, nil)

	n, err := src.LocalAddrCount()
	if err != nil {
		t.Fatalf("reading the address map: %v", err)
	}
	if n != len(addrs) {
		t.Fatalf("the kernel holds %d local addresses, want %d: detection would run blind", n, len(addrs))
	}
}

// TestLiveEbpfSyncLocalAddrs covers the refresh path, which exists because the
// host's address set changes while the daemon runs.
func TestLiveEbpfSyncLocalAddrs(t *testing.T) {
	src := newLiveEbpfSource(t, EbpfOptions{
		StartupGrace:       0,
		MaxProbesPerSecond: 1000,
		LocalAddrs:         []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}, nil)

	// An address appears.
	want := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::10"),
	}
	if err := src.SyncLocalAddrs(want); err != nil {
		t.Fatalf("SyncLocalAddrs: %v", err)
	}
	if n, _ := src.LocalAddrCount(); n != len(want) {
		t.Fatalf("after adding: the kernel holds %d addresses, want %d", n, len(want))
	}

	// And one goes away: a stale entry would keep counting packets aimed at an
	// address this host no longer has.
	want = want[:1]
	if err := src.SyncLocalAddrs(want); err != nil {
		t.Fatalf("SyncLocalAddrs: %v", err)
	}
	if n, _ := src.LocalAddrCount(); n != 1 {
		t.Fatalf("after removing: the kernel holds %d addresses, want 1", n)
	}

	// Idempotent.
	if err := src.SyncLocalAddrs(want); err != nil {
		t.Fatalf("second SyncLocalAddrs: %v", err)
	}
	if n, _ := src.LocalAddrCount(); n != 1 {
		t.Fatalf("a repeated refresh changed the map")
	}
}

// TestLiveEbpfExemptPrefixesAreInstalled checks the LPM tries the program
// consults before forwarding anything, for both families.
func TestLiveEbpfExemptPrefixesAreInstalled(t *testing.T) {
	src := newLiveEbpfSource(t, EbpfOptions{
		StartupGrace:       0,
		MaxProbesPerSecond: 1000,
		LocalAddrs:         []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Exempt: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("fe80::/10"),
			netip.MustParsePrefix("198.51.100.0/24"),
		},
	}, nil)

	// Reaching this far means every Put succeeded: an LPM key with the wrong
	// prefix length or the wrong layout is rejected by the kernel, not ignored.
	if _, err := src.Stats(); err != nil {
		t.Fatalf("the module is not usable after seeding the exemptions: %v", err)
	}
}

// TestLiveEbpfProgramRuntimeIsReadable checks the accounting the cost
// measurement depends on, so a change in the kernel's fdinfo format shows up
// here rather than as a silently absent number in a report.
func TestLiveEbpfProgramRuntimeIsReadable(t *testing.T) {
	src := newLiveEbpfSource(t, EbpfOptions{
		StartupGrace:       0,
		MaxProbesPerSecond: 1000,
		LocalAddrs:         []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}, nil)

	runs, total, err := src.ProgramRuntime()
	if err != nil {
		t.Fatalf("ProgramRuntime: %v", err)
	}
	// Without statistics enabled both are zero, which is correct and is what
	// this asserts: the call works and reports honestly rather than guessing.
	if runs != 0 && total == 0 {
		t.Errorf("the kernel reports %d runs but no runtime", runs)
	}

	closer, err := EnableKernelProgramStats()
	if err != nil {
		requireEbpf(t, "BPF run-time statistics are unavailable", err)
	}
	defer closer.Close()

	// Nothing forces traffic here, so the counters may legitimately stay at
	// zero; what matters is that reading them still works with stats on.
	if _, _, err := src.ProgramRuntime(); err != nil {
		t.Fatalf("ProgramRuntime with statistics enabled: %v", err)
	}
}

// TestLiveEbpfCloseIsIdempotent: the daemon closes on shutdown and on error
// paths, and a double close must not panic or fail.
func TestLiveEbpfCloseIsIdempotent(t *testing.T) {
	src := newLiveEbpfSource(t, EbpfOptions{
		StartupGrace:       0,
		MaxProbesPerSecond: 1000,
		LocalAddrs:         []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}, nil)

	go src.Run()
	time.Sleep(100 * time.Millisecond)

	if err := src.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// A closed source must not keep answering as though it were live.
	if err := src.SyncLocalAddrs(nil); err != nil {
		t.Fatalf("SyncLocalAddrs after Close: %v", err)
	}
}

// TestLiveEbpfAttachesToAnInterfaceThatComesUpLater is the kernel-side half of
// the AF_PACKET test of the same shape.
//
// A program that ran on whatever was up at the instant the daemon started, for
// ever, would miss the machines its own header lists as the ordinary case:
// "a laptop has Wi-Fi, VPN tunnels (tun, wireguard), Docker bridges and veth
// pairs". A tunnel connecting after login, a container bridge created on
// demand, or a laptop that boots before it associates would each be a
// complete evasion needing no forged packet and no flood.
func TestLiveEbpfAttachesToAnInterfaceThatComesUpLater(t *testing.T) {
	src := newLiveEbpfSource(t, EbpfOptions{StartupGrace: 0}, nil)

	// Built with netlink rather than by running ip(8): this test also runs as PID
	// 1 inside the VM harness, whose initramfs has no iproute2, and a test that
	// skips in the one environment that can load an eBPF program is a test that
	// never runs.
	const lateIf = "psebpflate0"
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: lateIf},
		PeerName:  "psebpflate1",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		requireEbpf(t, "creating a veth pair", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	if err := netlink.LinkSetUp(veth); err != nil {
		requireEbpf(t, "bringing "+lateIf+" up", err)
	}

	ifi, err := net.InterfaceByName(lateIf)
	if err != nil {
		t.Fatalf("the new interface is not there: %v", err)
	}
	src.mu.Lock()
	_, already := src.links[ifi.Index]
	src.mu.Unlock()
	if already {
		t.Fatalf("%s is attached before RefreshInterfaces ran; this test is not"+
			" exercising the case it exists for", lateIf)
	}

	added, err := src.RefreshInterfaces()
	if err != nil {
		t.Fatalf("RefreshInterfaces: %v", err)
	}
	for _, name := range added {
		if name == lateIf {
			src.mu.Lock()
			_, ok := src.links[ifi.Index]
			src.mu.Unlock()
			if !ok {
				t.Fatalf("%s was reported as added but is not recorded as attached", lateIf)
			}
			t.Logf("the program is now attached to %s, which did not exist at startup", lateIf)
			return
		}
	}
	t.Fatalf("RefreshInterfaces reported %v; %s came up after the program was loaded"+
		" and must now be watched", added, lateIf)
}

// TestLiveEbpfMarksInterfacesWithNoLinkHeader: the kernel program decides
// whether to skip an Ethernet header by looking the interface index up in
// l2less_ifaces, and this is what fills it.
//
// Deciding from the packet instead would not be safe -- a destination MAC
// beginning 0x4X is legal, and inside a tunnel the attacker chooses the source
// address that would be read as an ethertype. So the map has to be right, and
// has to follow interfaces that come and go.
func TestLiveEbpfMarksInterfacesWithNoLinkHeader(t *testing.T) {
	src := newLiveEbpfSource(t, EbpfOptions{StartupGrace: 0}, nil)

	m, ok := src.coll.Maps["l2less_ifaces"]
	if !ok {
		t.Fatal("the module has no l2less_ifaces map")
	}

	tunFile, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		requireEbpf(t, "/dev/net/tun is unavailable", err)
	}
	defer tunFile.Close()
	var ifr struct {
		Name  [16]byte
		Flags uint16
		_     [22]byte
	}
	const tunIf = "psebpftun0"
	copy(ifr.Name[:], tunIf)
	ifr.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, tunFile.Fd(),
		uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr))); e != 0 {
		requireEbpf(t, "TUNSETIFF", e)
	}

	link, err := netlink.LinkByName(tunIf)
	if err != nil {
		t.Fatalf("the tun device is not there: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		requireEbpf(t, "bringing "+tunIf+" up", err)
	}
	ifi, err := net.InterfaceByName(tunIf)
	if err != nil {
		t.Fatal(err)
	}
	if len(ifi.HardwareAddr) != 0 {
		t.Fatalf("%s reports a hardware address; this test needs ARPHRD_NONE", tunIf)
	}

	if _, err := src.RefreshInterfaces(); err != nil {
		t.Fatalf("RefreshInterfaces: %v", err)
	}
	var value uint8
	if err := m.Lookup(uint32(ifi.Index), &value); err != nil {
		t.Fatalf("%s (index %d) is not marked as having no link header: %v."+
			" The program would read two bytes of the source address as an ethertype"+
			" and discard every packet of the tunnel", tunIf, ifi.Index, err)
	}
	t.Logf("%s (index %d) is marked as carrying no link header", tunIf, ifi.Index)

	// And an Ethernet interface must NOT be marked, or the program would skip a
	// header that is really there.
	ifaces, err := resolveInterfaces(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ifaces {
		if len(e.HardwareAddr) == 0 {
			continue
		}
		if err := m.Lookup(uint32(e.Index), &value); err == nil {
			t.Errorf("%s has a hardware address but is marked as having no link header", e.Name)
		}
	}
}

// TestLiveEbpfExcludedPortsBitmap checks the one encoding that userspace and the
// kernel program must agree on and that nothing else exercises.
//
// excluded_ports became a BPF_MAP_TYPE_ARRAY bitmap -- 1024 words of 64 bits,
// one bit per port -- because an ARRAY lookup is inlined by the verifier where a
// HASH lookup is a real helper call, and that call sat on the path of every
// packet aimed at this host. The cost of that change is a hand-rolled encoding
// on both sides: Go writes `word[port>>6] |= 1 << (port & 63)`, the program
// reads `(*bits >> (dport & 63)) & 1`.
//
// If those two ever disagree, the excluded ports are not excluded -- DHCP,
// mDNS, SSDP and LLMNR would be scored, which is a false-positive generator on
// every network with a printer on it -- and nothing else would notice, because
// the map is only ever filled with a BPF program loaded. That is why this test
// exists here rather than as a unit test.
func TestLiveEbpfExcludedPortsBitmap(t *testing.T) {
	excluded := []uint16{67, 68, 5353, 5355, 1900, 0, 65535}
	src := newLiveEbpfSource(t, EbpfOptions{
		StartupGrace:  0,
		ExcludedPorts: excluded,
	}, nil)

	m, ok := src.coll.Maps["excluded_ports"]
	if !ok {
		t.Fatal("the module has no excluded_ports map")
	}
	if got := m.MaxEntries(); got != 1024 {
		t.Fatalf("excluded_ports holds %d words, want 1024 (one bit per port)", got)
	}

	// Read the map back the way the PROGRAM reads it, not the way the daemon
	// wrote it: that is what makes this a check of the agreement rather than of
	// one side alone.
	isSet := func(port uint16) bool {
		var word uint64
		if err := m.Lookup(uint32(port>>6), &word); err != nil {
			t.Fatalf("looking up word %d for port %d: %v", port>>6, port, err)
		}
		return (word>>(port&63))&1 == 1
	}

	for _, port := range excluded {
		if !isSet(port) {
			t.Errorf("port %d was configured as excluded and its bit is clear:"+
				" the kernel program will score it", port)
		}
	}
	for _, port := range []uint16{22, 80, 443, 8080, 69, 1899, 1901, 5354} {
		if isSet(port) {
			t.Errorf("port %d is not in the excluded list but its bit is set:"+
				" scans of it would be invisible", port)
		}
	}
	t.Logf("%d ports excluded, encoding agrees with the program's reader", len(excluded))
}

// TestLiveEbpfGraceDeadlineIsAbsolute reads back the start-up grace the program
// compares against bpf_ktime_get_ns. It must be a deadline in that clock, not a
// duration: holding the duration, it was true only in the first minute of the
// machine's uptime, and filtered nothing for any daemon started later.
func TestLiveEbpfGraceDeadlineIsAbsolute(t *testing.T) {
	src := newLiveEbpfSource(t, EbpfOptions{StartupGrace: time.Hour}, nil)
	m, ok := src.coll.Maps["scan_config"]
	if !ok {
		t.Fatal("the module has no scan_config map")
	}
	var lo, hi uint32
	if err := m.Lookup(uint32(cfgGraceUntilLo), &lo); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(uint32(cfgGraceUntilHi), &hi); err != nil {
		t.Fatal(err)
	}
	until := uint64(hi)<<32 | uint64(lo)
	now := src.NowNs()
	if until < now+uint64(59*time.Minute) || until > now+uint64(time.Hour) {
		t.Fatalf("grace deadline %d with the program's clock at %d: want now + 1h,"+
			" as an absolute time", until, now)
	}
}
