//go:build linux

package portscan

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Live end-to-end test: a real nmap process scans this host, the AF_PACKET
// source reads the real frames off a real interface, and the engine must
// report the scan.
//
// This is the only test in the package that exercises the whole chain rather
// than a component of it, and it is the one that can catch a mistake no unit
// test can: a socket option that silently drops traffic, a filter that
// excludes the very packets we need, a link layer whose header is not where we
// expect it.
//
// It needs CAP_NET_RAW and CAP_NET_ADMIN, which an unprivileged user namespace
// provides:
//
//	unshare -Urn go test -run TestLive ./portscan/
//
// testdata/run_live_test.sh does exactly that.

// liveHost accepts the addresses configured on the test interface.
type liveHost struct {
	local map[netip.Addr]bool
}

func (h *liveHost) IsLocalUnicast(a netip.Addr) bool { return h.local[a] }
func (h *liveHost) IsListening(uint8, uint16) bool   { return false }
func (h *liveHost) HasConnection(*Probe) bool        { return false }
func (h *liveHost) IsOnLink(netip.Addr) bool         { return true }
func (h *liveHost) IsExempt(netip.Addr) bool         { return false }

// requireLiveEnv skips unless raw sockets and the tools are available.
func requireLiveEnv(t *testing.T) {
	t.Helper()
	requireDisposableNetwork(t, "PORTSCAN_REQUIRE_LIVE")
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if os.Getenv("PORTSCAN_REQUIRE_LIVE") == "1" {
			t.Fatalf("PORTSCAN_REQUIRE_LIVE=1 but AF_PACKET is unavailable: %v", err)
		}
		t.Skipf("AF_PACKET raw sockets unavailable (%v); run under: unshare -Urn go test -run TestLive ./portscan/", err)
	}
	unix.Close(fd)
	for _, bin := range []string{"ip", "nmap"} {
		if _, err := exec.LookPath(bin); err != nil {
			if os.Getenv("PORTSCAN_REQUIRE_LIVE") == "1" {
				t.Fatalf("PORTSCAN_REQUIRE_LIVE=1 but %s is not installed", bin)
			}
			t.Skipf("%s is not installed", bin)
		}
	}
}

// lab is the two-namespace test topology.
//
//	this namespace (victim)              peer namespace (attacker)
//	psv0  10.88.0.1/24  <------------->  psv1  10.88.0.2/24
//	      fd00:88::1/64                        fd00:88::2/64
//
// The two ends MUST live in different network namespaces. With both ends in
// one namespace the kernel short-circuits traffic between two of its own
// addresses through the loopback path, the frames never reach the veth, and
// the packet socket legitimately sees nothing -- which looks exactly like a
// broken socket.
type lab struct {
	victimIf  string
	victim4   netip.Addr
	attacker4 netip.Addr
	peerPID   int
}

// attackerCmd builds a command that runs inside the peer namespace.
func (l *lab) attackerCmd(name string, args ...string) *exec.Cmd {
	full := append([]string{"-t", strconv.Itoa(l.peerPID), "-n", name}, args...)
	return exec.Command("nsenter", full...)
}

func setupLab(t *testing.T) *lab {
	t.Helper()
	const (
		vif = "psv0"
		aif = "psv1"
	)
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	if _, err := exec.LookPath("nsenter"); err != nil {
		liveSkipf(t, "nsenter is not installed: %v", err)
	}

	_ = exec.Command("ip", "link", "del", vif).Run()
	run("link", "add", vif, "type", "veth", "peer", "name", aif)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", vif).Run() })

	// A parked process whose network namespace we can address by PID.
	peer := exec.Command("unshare", "-n", "sleep", "600")
	if err := peer.Start(); err != nil {
		t.Fatalf("starting the peer namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = peer.Process.Kill()
		_, _ = peer.Process.Wait()
	})
	time.Sleep(300 * time.Millisecond)
	pid := peer.Process.Pid

	run("link", "set", aif, "netns", strconv.Itoa(pid))
	run("addr", "add", "10.88.0.1/24", "dev", vif)
	run("link", "set", "lo", "up")
	run("link", "set", vif, "up")

	l := &lab{
		victimIf:  vif,
		victim4:   netip.MustParseAddr("10.88.0.1"),
		attacker4: netip.MustParseAddr("10.88.0.2"),
		peerPID:   pid,
	}
	for _, args := range [][]string{
		{"addr", "add", "10.88.0.2/24", "dev", aif},
		{"link", "set", "lo", "up"},
		{"link", "set", aif, "up"},
	} {
		if out, err := l.attackerCmd("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("peer ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	time.Sleep(400 * time.Millisecond)
	return l
}

// TestLiveAFPacketDetectsRealNmapScan is the end-to-end check.
func TestLiveAFPacketDetectsRealNmapScan(t *testing.T) {
	requireLiveEnv(t)
	l := setupLab(t)
	victimIf, victim4 := l.victimIf, l.victim4

	host := &liveHost{local: map[netip.Addr]bool{victim4: true}}
	// Also accept whatever else ended up on the interface, so a link-local
	// address does not make a probe look like it was aimed elsewhere.
	if ifi, err := net.InterfaceByName(victimIf); err == nil {
		if addrs, err := ifi.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if na, ok := netip.AddrFromSlice(ipn.IP); ok {
						host.local[na.Unmap()] = true
					}
				}
			}
		}
	}

	cfg := testConfig()
	cfg.AlertsPerMinute = maxAlertsPerMinute
	cfg.ReportCooldown = 0

	var (
		mu     sync.Mutex
		events []*ScanEvent
		probes int
	)

	src, err := NewAFPacketSource([]string{victimIf}, afPacketDefaultBudget, nil, nil)
	if err == nil {
		t.Fatal("NewAFPacketSource accepted a nil onProbe callback")
	}
	_ = src

	var engine *Engine
	source, err := NewAFPacketSource([]string{victimIf}, afPacketDefaultBudget,
		func(p *Probe) {
			mu.Lock()
			probes++
			mu.Unlock()
			if ev := engine.Process(p); ev != nil {
				mu.Lock()
				events = append(events, ev)
				mu.Unlock()
			}
		},
		func(err error) { t.Logf("source error: %v", err) },
	)
	if err != nil {
		t.Fatalf("NewAFPacketSource: %v", err)
	}
	defer source.Close()

	engine, err = NewEngine(cfg, host, 0)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	engine.SetWallClockAnchor(source.StartedAt(), 0)

	done := make(chan struct{})
	go func() { source.Run(); close(done) }()
	time.Sleep(400 * time.Millisecond)

	// The real scan, run from the attacker namespace so the frames actually
	// traverse the veth. -Pn skips host discovery, which would otherwise
	// declare the victim down: nothing listens on it and it answers no ping.
	cmd := l.attackerCmd("nmap", "-sS", "-Pn", "-p", "1-200", "-n",
		"--max-retries", "0", "-T4", victim4.String())
	out, err := cmd.CombinedOutput()
	t.Logf("nmap exit=%v output:\n%s", err, out)

	// Give the reader a moment to drain.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(events)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	source.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	t.Logf("observed %d probes, %d scan events", probes, len(events))
	if probes == 0 {
		t.Fatal("the AF_PACKET source saw no packet at all: the socket, the filter or the interface binding is wrong")
	}
	if len(events) == 0 {
		t.Fatalf("a real nmap -sS scan over %d observed probes was not reported", probes)
	}

	ev := events[0]
	if ev.Method != MethodSYN {
		t.Errorf("method = %v (%s), want %v for nmap -sS", ev.Method, ev.MethodDetail, MethodSYN)
	}
	if !ev.HasMAC {
		t.Error("no source MAC recovered; SOCK_RAW should preserve the Ethernet header")
	}
	if ev.DistinctPorts < 5 {
		t.Errorf("distinct ports = %d, want several", ev.DistinctPorts)
	}
	if !ev.HasTCPEvidence {
		t.Error("HasTCPEvidence not set for a TCP SYN scan")
	}
	t.Logf("detected: %s from %v, %d ports [%d..%d], score=%d, flags=%s, mac=%02x:%02x:%02x:%02x:%02x:%02x",
		ev.MethodDetail, ev.Src, ev.DistinctPorts, ev.MinPort, ev.MaxPort, ev.Score, ev.FlagsSummary,
		ev.SrcMAC[0], ev.SrcMAC[1], ev.SrcMAC[2], ev.SrcMAC[3], ev.SrcMAC[4], ev.SrcMAC[5])
}

// TestLiveAFPacketIgnoresOutgoing checks that the source does not feed the
// host's own outbound traffic back into detection. Without the PACKET_HOST
// filter, every reply this host sends would be parsed as if it had arrived.
func TestLiveAFPacketIgnoresOutgoing(t *testing.T) {
	requireLiveEnv(t)
	l := setupLab(t)
	victimIf, victim4, attacker4 := l.victimIf, l.victim4, l.attacker4

	var (
		mu       sync.Mutex
		fromSelf int
		total    int
	)
	source, err := NewAFPacketSource([]string{victimIf}, afPacketDefaultBudget,
		func(p *Probe) {
			mu.Lock()
			total++
			if p.Src == victim4 {
				fromSelf++
			}
			mu.Unlock()
		}, nil)
	if err != nil {
		t.Fatalf("NewAFPacketSource: %v", err)
	}
	defer source.Close()

	done := make(chan struct{})
	go func() { source.Run(); close(done) }()
	time.Sleep(300 * time.Millisecond)

	// Traffic in both directions: an inbound scan, and outbound pings whose
	// replies leave through the same interface.
	_ = l.attackerCmd("nmap", "-sS", "-Pn", "-p", "1-50", "-n",
		"--max-retries", "0", victim4.String()).Run()
	_ = exec.Command("ping", "-c", "3", "-W", "1", attacker4.String()).Run()
	time.Sleep(500 * time.Millisecond)

	source.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	t.Logf("observed %d probes, %d of them with our own address as the source", total, fromSelf)
	if fromSelf != 0 {
		t.Errorf("%d outbound packets were delivered as if inbound; the PACKET_HOST filter is not working", fromSelf)
	}
}

// TestLiveAFPacketWatchesAnInterfaceThatComesUpLater checks, on real
// interfaces, that one created after the source was built is watched.
//
// An interface list fixed to whatever was up at the instant the source was
// built would not do. On the machines this feature targets that is not an
// edge case: a VPN tunnel connects after login, a container bridge is created
// on demand, and a laptop that boots before it associates has wlan0 DOWN at
// start -- so the primary interface of the machine would never be watched at
// all, while the daemon reported detection as running. Scanning over such an
// interface would need no forged packet and no flood.
func TestLiveAFPacketWatchesAnInterfaceThatComesUpLater(t *testing.T) {
	requireLiveEnv(t)
	l := setupLab(t)

	var mu sync.Mutex
	seen := map[uint32]int{}
	src, err := NewAFPacketSource(nil, afPacketDefaultBudget,
		func(p *Probe) {
			mu.Lock()
			seen[p.IfaceIndex]++
			mu.Unlock()
		},
		func(error) {})
	if err != nil {
		t.Fatalf("NewAFPacketSource: %v", err)
	}
	defer src.Close()
	go src.Run()
	time.Sleep(200 * time.Millisecond)

	// A second veth pair, created after the source was built -- a VPN tunnel or
	// a container bridge, as far as this source is concerned.
	const lateIf = "pslate0"
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			liveSkipf(t, "ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	run("link", "add", lateIf, "type", "veth", "peer", "name", "pslate1")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", lateIf).Run() })
	run("addr", "add", "10.99.0.1/24", "dev", lateIf)
	run("link", "set", lateIf, "up")
	// The far end goes into the peer namespace. With both ends here the kernel
	// short-circuits traffic between two of its own addresses and the frames
	// never reach the veth -- which looks exactly like a blind socket.
	run("link", "set", "pslate1", "netns", strconv.Itoa(l.peerPID))
	if out, err := l.attackerCmd("ip", "addr", "add", "10.99.0.9/24", "dev", "pslate1").CombinedOutput(); err != nil {
		liveSkipf(t, "addressing the peer end: %v: %s", err, out)
	}
	if out, err := l.attackerCmd("ip", "link", "set", "pslate1", "up").CombinedOutput(); err != nil {
		liveSkipf(t, "bringing the peer end up: %v: %s", err, out)
	}

	late, err := net.InterfaceByName(lateIf)
	if err != nil {
		t.Fatalf("the new interface is not there: %v", err)
	}

	added, err := src.RefreshInterfaces()
	if err != nil {
		t.Fatalf("RefreshInterfaces: %v", err)
	}
	found := false
	for _, name := range added {
		if name == lateIf {
			found = true
		}
	}
	if !found {
		t.Fatalf("RefreshInterfaces reported %v; %s came up after the source was built"+
			" and must now be watched", added, lateIf)
	}

	// And it must actually carry probes, not merely be bound: a socket nobody
	// reads is the same blind spot with an extra file descriptor.
	time.Sleep(200 * time.Millisecond)
	if out, err := l.attackerCmd("nmap", "-sS", "-Pn", "-n", "--max-retries", "0",
		"-p", "70-90", "10.99.0.1").CombinedOutput(); err != nil {
		liveSkipf(t, "nmap over the late interface: %v: %s", err, out)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := seen[uint32(late.Index)]
		mu.Unlock()
		if n > 0 {
			t.Logf("%d probes observed on %s, which did not exist when the source was built",
				n, lateIf)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	got := seen
	mu.Unlock()
	t.Fatalf("no probe arrived on %s (index %d); observed %v -- the interface is bound"+
		" but nothing is reading it", lateIf, late.Index, got)
}

// TestLiveAFPacketNamedInterfaceThatIsNotThereYet covers a named interface
// list with one name missing at start-up -- eth0 and tun0, with the VPN down
// at boot.
//
// Two failures are possible there: switching detection off everywhere,
// including on the interface that does exist, or dropping the missing name
// without a word, so that the operator is told nothing until the interface
// appears, and never if the name is a typo. The wiki promises both halves --
// started on what exists, told about what does not, and picked up when it
// appears.
func TestLiveAFPacketNamedInterfaceThatIsNotThereYet(t *testing.T) {
	requireLiveEnv(t)
	setupLab(t)

	const lateIf = "psnamed0"
	var mu sync.Mutex
	var reported []error
	src, err := NewAFPacketSource([]string{"psv0", lateIf}, afPacketDefaultBudget,
		func(*Probe) {},
		func(err error) {
			mu.Lock()
			reported = append(reported, err)
			mu.Unlock()
		})
	if err != nil {
		t.Fatalf("NewAFPacketSource with one of two named interfaces present: %v"+
			" -- one absent name must not switch detection off on the other", err)
	}
	defer src.Close()
	go src.Run()

	mu.Lock()
	var said error
	for _, e := range reported {
		if strings.Contains(e.Error(), lateIf) {
			said = e
		}
	}
	mu.Unlock()
	if said == nil {
		t.Fatalf("started without %s and said nothing about it; reported %v", lateIf, reported)
	}
	if !IsDegradation(said) {
		t.Errorf("%q is not reported as a degradation, so the daemon does not show it"+
			" to the user as one", said)
	}

	if out, err := exec.Command("ip", "link", "add", lateIf,
		"type", "veth", "peer", "name", lateIf+"p").CombinedOutput(); err != nil {
		liveSkipf(t, "creating a veth pair: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", lateIf).Run() })
	added, err := src.RefreshInterfaces()
	if err != nil {
		t.Fatalf("RefreshInterfaces: %v", err)
	}
	if len(added) != 1 || added[0] != lateIf {
		t.Fatalf("RefreshInterfaces reported %v after %s appeared; want exactly [%s]",
			added, lateIf, lateIf)
	}

	// The one case that is refused: nothing in the list exists.
	if s, err := NewAFPacketSource([]string{"psabsent0", "psabsent1"}, afPacketDefaultBudget,
		func(*Probe) {}, func(error) {}); err == nil {
		s.Close()
		t.Fatal("started with none of the named interfaces present; that is" +
			" detection running on nothing, and must be an error")
	}
}

// TestLiveAFPacketReleasesVanishedInterfaces covers the leak that re-evaluating
// interfaces makes possible.
//
// A RefreshInterfaces that only ever added would open a socket for every
// interface it did not yet know and never close one for an interface that had
// gone. An AF_PACKET socket costs a descriptor AND a kernel receive buffer --
// 208 KB by default, neither pageable nor counted in the daemon's RSS. The
// trigger is ordinary on the machines this feature targets: every `docker run`
// creates a veth on the host, every VPN reconnection an interface. Measured
// over five create/delete cycles with such a refresh: twelve sockets held for
// two live interfaces, growing monotonically.
func TestLiveAFPacketReleasesVanishedInterfaces(t *testing.T) {
	requireLiveEnv(t)
	setupLab(t)

	src, err := NewAFPacketSource(nil, afPacketDefaultBudget, func(*Probe) {}, func(error) {})
	if err != nil {
		t.Fatalf("NewAFPacketSource: %v", err)
	}
	defer src.Close()
	go src.Run()
	time.Sleep(100 * time.Millisecond)

	held := func() int {
		src.mu.Lock()
		defer src.mu.Unlock()
		return len(src.socks)
	}
	openFDs := func() int {
		ents, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			liveSkipf(t, "cannot read /proc/self/fd: %v", err)
		}
		return len(ents)
	}

	baseSocks, baseFDs := held(), openFDs()
	t.Logf("after construction: %d sockets, %d open fds", baseSocks, baseFDs)

	for round := 0; round < 5; round++ {
		name := fmt.Sprintf("psleak%d", round)
		if out, err := exec.Command("ip", "link", "add", name,
			"type", "veth", "peer", "name", name+"p").CombinedOutput(); err != nil {
			liveSkipf(t, "creating a veth pair: %v: %s", err, out)
		}
		if out, err := exec.Command("ip", "link", "set", name, "up").CombinedOutput(); err != nil {
			liveSkipf(t, "bringing %s up: %v: %s", name, err, out)
		}
		if _, err := src.RefreshInterfaces(); err != nil {
			t.Fatalf("RefreshInterfaces: %v", err)
		}
		if out, err := exec.Command("ip", "link", "del", name).CombinedOutput(); err != nil {
			t.Fatalf("deleting %s: %v: %s", name, err, out)
		}
		if _, err := src.RefreshInterfaces(); err != nil {
			t.Fatalf("RefreshInterfaces after deletion: %v", err)
		}
		t.Logf("round %d: sockets held=%d, open fds=%d", round, held(), openFDs())
	}

	if got := held(); got != baseSocks {
		t.Errorf("%d sockets held for the same %d live interfaces after five"+
			" create/delete cycles: one socket and one kernel receive buffer leak"+
			" per interface the daemon has ever seen", got, baseSocks)
	}
	if got := openFDs(); got > baseFDs {
		t.Errorf("%d open descriptors, started at %d: the leak is visible in /proc/self/fd",
			got, baseFDs)
	}
}

// createTestTun makes an IFF_TUN|IFF_NO_PI device: ARPHRD_NONE, no hardware
// address, and therefore no link header on the frames it delivers.
func createTestTun(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		liveSkipf(t, "/dev/net/tun is unavailable: %v", err)
	}
	var ifr struct {
		Name  [16]byte
		Flags uint16
		_     [22]byte
	}
	copy(ifr.Name[:], name)
	ifr.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr))); e != 0 {
		f.Close()
		liveSkipf(t, "TUNSETIFF on %s: %v", name, e)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// tunSYN builds a bare IPv4 SYN: no Ethernet header, because a tun device has
// none.
func tunSYN(src, dst netip.Addr, dport uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], 40)
	pkt[8] = 64
	pkt[9] = ProtoTCP
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(pkt[20:], 40000)
	binary.BigEndian.PutUint16(pkt[22:], dport)
	pkt[32] = 0x50
	pkt[33] = TCPSyn
	return pkt
}

// TestLiveAFPacketSeesATunnelWithNoLinkHeader checks that an interface with no
// link header is actually read.
//
// A tun device -- WireGuard, OpenVPN in tun mode, Tailscale -- and ppp0, sit0,
// gre and xfrm interfaces are ARPHRD_NONE: the frame begins at the IP header,
// with no Ethernet header. A packet source that read bytes 12-13 as an
// ethertype anyway would be reading two bytes of the SOURCE ADDRESS, so the
// test "is this 0x0800 or 0x86dd" would fail for every packet of every tunnel,
// and a classic BPF filter written the same way would drop them in the kernel.
//
// Measured that way: 20 SYNs injected into a tun device produced 0 probes,
// while the same 20 SYNs on an Ethernet device produced 20 -- and the daemon
// reported the tunnel as watched throughout. A VPN is one of the interfaces
// this feature exists to cover.
func TestLiveAFPacketSeesATunnelWithNoLinkHeader(t *testing.T) {
	requireLiveEnv(t)

	const tunIf = "pstun0"
	tun := createTestTun(t, tunIf)

	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			liveSkipf(t, "ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	run("addr", "add", "10.9.9.1/24", "dev", tunIf)
	run("link", "set", tunIf, "up")

	ifi, err := net.InterfaceByName(tunIf)
	if err != nil {
		t.Fatalf("the tun device is not there: %v", err)
	}
	if len(ifi.HardwareAddr) != 0 {
		t.Fatalf("%s has a hardware address (%v); this test needs an ARPHRD_NONE device",
			tunIf, ifi.HardwareAddr)
	}

	var mu sync.Mutex
	var probes []Probe
	src, err := NewAFPacketSource([]string{tunIf}, afPacketDefaultBudget,
		func(p *Probe) {
			mu.Lock()
			probes = append(probes, *p)
			mu.Unlock()
		},
		func(error) {})
	if err != nil {
		t.Fatalf("NewAFPacketSource on %s: %v", tunIf, err)
	}
	defer src.Close()
	go src.Run()
	time.Sleep(200 * time.Millisecond)

	scanner := netip.MustParseAddr("10.9.9.66")
	victimAddr := netip.MustParseAddr("10.9.9.1")
	const sent = 20
	for i := 0; i < sent; i++ {
		if _, err := tun.Write(tunSYN(scanner, victimAddr, uint16(20+i))); err != nil {
			t.Fatalf("writing into the tunnel: %v", err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(probes)
		mu.Unlock()
		if n >= sent {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	got := append([]Probe(nil), probes...)
	mu.Unlock()

	if len(got) == 0 {
		t.Fatalf("%d SYNs injected into %s produced no probes at all: every packet of"+
			" every tunnel is invisible while the daemon reports the interface as watched",
			sent, tunIf)
	}
	t.Logf("%d of %d SYNs delivered from a device with no link header", len(got), sent)

	p := got[0]
	if p.Src != scanner || p.Dst != victimAddr {
		t.Errorf("probe carries %s -> %s, want %s -> %s", p.Src, p.Dst, scanner, victimAddr)
	}
	if p.Proto != ProtoTCP || !p.TCPFlagsValid || p.TCPFlags != TCPSyn {
		t.Errorf("proto/flags = %d/%#02x valid=%v, want %d/%#02x valid=true",
			p.Proto, p.TCPFlags, p.TCPFlagsValid, ProtoTCP, TCPSyn)
	}
	if p.HasMAC {
		t.Error("a probe from a device with no link layer must not claim a source MAC")
	}
}

// TestLiveAFPacketBudgetIsApplied: the AF_PACKET budget is applied where
// packets are read. It had unit tests of its own and none of its call: taking
// the call out of the read loop left every suite green, and a flood of forged
// sources reached the engine whole, with rate_limited at zero.
func TestLiveAFPacketBudgetIsApplied(t *testing.T) {
	requireLiveEnv(t)
	l := setupLab(t)
	const budget = 20
	var n atomic.Int64
	src, err := NewAFPacketSource([]string{l.victimIf}, budget,
		func(*Probe) { n.Add(1) }, func(error) {})
	if err != nil {
		t.Fatalf("NewAFPacketSource: %v", err)
	}
	defer src.Close()
	go src.Run()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	out, err := l.attackerCmd("nmap", "-sS", "-Pn", "-T5", "--min-rate", "2000", "-p", "1-2000", "-n",
		l.victim4.String()).CombinedOutput()
	if err != nil {
		t.Fatalf("nmap: %v: %s", err, out)
	}
	time.Sleep(200 * time.Millisecond)
	elapsed := time.Since(start)
	stats, _ := src.Stats()
	limit := int64(budget * (int(elapsed/time.Second) + 2))
	if got := n.Load(); got > limit || stats["rate_limited"] == 0 {
		t.Fatalf("%d probes reached the engine in %v with a budget of %d/s (rate_limited=%d)",
			got, elapsed, budget, stats["rate_limited"])
	}
}

// TestHelperUDPStream is not a test. The live budget test runs this binary in
// the peer's namespace to send a steady UDP stream, the shape of an HTTP/3
// download, so the live test needs nothing but itself and nmap.
func TestHelperUDPStream(t *testing.T) {
	target := os.Getenv("PORTSCAN_UDP_STREAM_TO")
	if target == "" {
		t.Skip("run by TestLiveAFPacketOnePeerDoesNotBlindAScan")
	}
	rate, _ := strconv.Atoi(os.Getenv("PORTSCAN_UDP_STREAM_RATE"))
	from, err := net.ResolveUDPAddr("udp4", os.Getenv("PORTSCAN_UDP_STREAM_FROM")+":0")
	if err != nil {
		t.Fatal(err)
	}
	to, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp4", from, to)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := make([]byte, 1200)
	start := time.Now()
	for sent := 0; time.Since(start) < 6*time.Second; sent++ {
		_, _ = conn.Write(payload)
		if ahead := time.Duration(sent)*time.Second/time.Duration(rate) - time.Since(start); ahead > 0 {
			time.Sleep(ahead)
		}
	}
}

// TestLiveAFPacketOnePeerDoesNotBlindAScan: if the fallback's only budget were
// the aggregate one, spent before the parse, ordinary inbound traffic would
// spend it. Measured that way: beside one peer streaming 20000 UDP packets a
// second to an open port, 182 of a scan's 1000 SYNs reached the engine, and
// nothing reported it. Each source is held to its own budget first.
func TestLiveAFPacketOnePeerDoesNotBlindAScan(t *testing.T) {
	requireLiveEnv(t)
	l := setupLab(t)
	sink, err := net.ListenPacket("udp4", l.victim4.String()+":4433")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			if _, _, err := sink.ReadFrom(b); err != nil {
				return
			}
		}
	}()
	var syns atomic.Int64
	src, err := NewAFPacketSource([]string{l.victimIf}, afPacketDefaultBudget,
		func(p *Probe) {
			if p.Proto == ProtoTCP && p.TCPFlags == TCPSyn {
				syns.Add(1)
			}
		}, func(error) {})
	if err != nil {
		t.Fatalf("NewAFPacketSource: %v", err)
	}
	defer src.Close()
	go src.Run()
	time.Sleep(200 * time.Millisecond)

	// The stream comes from a second address of the peer: from the scanner's
	// own, it would be the scanner spending its own budget.
	const peer = "10.88.0.3"
	if out, err := l.attackerCmd("ip", "addr", "add", peer+"/24", "dev", "psv1").CombinedOutput(); err != nil {
		t.Fatalf("adding the peer address: %v: %s", err, out)
	}
	stream := l.attackerCmd(os.Args[0], "-test.run=^TestHelperUDPStream$")
	stream.Env = append(os.Environ(), "PORTSCAN_UDP_STREAM_TO="+l.victim4.String()+":4433",
		"PORTSCAN_UDP_STREAM_FROM="+peer, "PORTSCAN_UDP_STREAM_RATE=20000")
	if err := stream.Start(); err != nil {
		t.Fatalf("starting the stream: %v", err)
	}
	time.Sleep(time.Second)
	out, err := l.attackerCmd("nmap", "-sS", "-Pn", "-n", "--max-retries", "0",
		"--min-rate", "200", "--max-rate", "200", "-p", "1-1000", l.victim4.String()).CombinedOutput()
	if err != nil {
		t.Fatalf("nmap: %v: %s", err, out)
	}
	if err := stream.Wait(); err != nil {
		t.Fatalf("the stream: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	stats, _ := src.Stats()
	// On a loaded machine the socket's receive buffer can overflow and lose a
	// few SYNs; that loss is the kernel's, counted in kernel_dropped and
	// reported as degraded detection. The budgets must lose none: an
	// aggregate-only budget would let 202 of the 1000 through.
	got := syns.Load()
	if got < 990 && (stats["kernel_dropped"] == 0 || got < 900) {
		t.Errorf("%d of the scan's 1000 SYNs reached the engine beside one busy peer (%v)", got, stats)
	}
	if stats["source_rate_limited"] == 0 || stats["rate_limited"] != 0 {
		t.Errorf("one busy peer was counted as %v: only its own budget should refuse it", stats)
	}
}

// liveSkipf skips when the environment cannot run a live AF_PACKET test, and
// fails instead under PORTSCAN_REQUIRE_LIVE=1: CI sets it so that a runner
// missing a piece -- nsenter, a veth pair, a tun device -- cannot pass with
// the test unrun.
func liveSkipf(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("PORTSCAN_REQUIRE_LIVE") == "1" {
		t.Fatalf("PORTSCAN_REQUIRE_LIVE=1 but "+format, args...)
	}
	t.Skipf(format, args...)
}
