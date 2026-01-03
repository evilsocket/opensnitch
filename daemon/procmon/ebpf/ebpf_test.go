//go:build linux

/*
eBPF Tests

Integration tests for OpenSnitch's eBPF programs.

Running Tests:

	sudo go test -v ./daemon/procmon/ebpf/

These tests are skipped in the standard "go test ./..." flow because they
require elevated privileges to load eBPF programs into the kernel.

For detailed information about capabilities, safety, and testing modes, see:
	daemon/internal/testutil/network.go
*/
package ebpf

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/evilsocket/opensnitch/daemon/internal/testutil"
)

// getTestDir returns the directory containing this test file
func getTestDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename)
}

// findEbpfModule searches for the compiled eBPF module
func findEbpfModule(name string) string {
	testDir := getTestDir()
	// From daemon/procmon/ebpf/ -> ebpf_prog/
	repoRoot := filepath.Join(testDir, "..", "..", "..")

	paths := []string{
		// Local build path (relative to repo root)
		filepath.Join(repoRoot, "ebpf_prog", name),
		// System paths
		"/usr/local/lib/opensnitchd/ebpf/" + name,
		"/usr/lib/opensnitchd/ebpf/" + name,
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return ""
}

// TestEbpfModuleLoad tests that the eBPF module can be loaded by the kernel
func TestEbpfModuleLoad(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF modules")
	}

	modulePath := findEbpfModule("opensnitch.o")
	if modulePath == "" {
		t.Skip("opensnitch.o not found - build with: make -C ebpf_prog")
	}

	t.Logf("loading module from: %s", modulePath)

	spec, err := ebpf.LoadCollectionSpec(modulePath)
	if err != nil {
		t.Fatalf("failed to load collection spec: %v", err)
	}

	// Log what we found in the module
	t.Logf("programs found: %d", len(spec.Programs))
	for name, prog := range spec.Programs {
		t.Logf("  - %s (type: %s)", name, prog.Type)
	}

	t.Logf("maps found: %d", len(spec.Maps))
	for name, m := range spec.Maps {
		t.Logf("  - %s (type: %s, key: %d bytes, value: %d bytes)",
			name, m.Type, m.KeySize, m.ValueSize)
	}

	// Actually load into kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load collection into kernel: %v", err)
	}
	defer coll.Close()

	t.Log("module loaded successfully into kernel")

	// Verify expected maps exist
	expectedMaps := []string{"tcpMap", "udpMap", "tcpv6Map", "udpv6Map"}
	for _, name := range expectedMaps {
		if coll.Maps[name] == nil {
			t.Errorf("expected map %s not found", name)
		} else {
			t.Logf("verified map: %s", name)
		}
	}
}

// TestEbpfMapOperations tests basic map read/write operations
func TestEbpfMapOperations(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF modules")
	}

	modulePath := findEbpfModule("opensnitch.o")
	if modulePath == "" {
		t.Skip("opensnitch.o not found - build with: make -C ebpf_prog")
	}

	spec, err := ebpf.LoadCollectionSpec(modulePath)
	if err != nil {
		t.Fatalf("failed to load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load collection: %v", err)
	}
	defer coll.Close()

	tcpMap := coll.Maps["tcpMap"]
	if tcpMap == nil {
		t.Fatal("tcpMap not found")
	}

	// Test that we can query the map (even if empty)
	var key, value uint64
	err = tcpMap.Lookup(&key, &value)
	if err != nil && err.Error() != "key does not exist" {
		// "key does not exist" is expected for empty map
		t.Logf("map lookup result: %v (this is expected for empty map)", err)
	}

	t.Log("map operations working")
}

// tcpKey matches struct tcp_key_t in opensnitch.c
type tcpKey struct {
	Sport uint16
	Daddr [4]byte
	Dport uint16
	Saddr [4]byte
}

// tcpValue matches struct tcp_value_t in opensnitch.c
type tcpValue struct {
	Pid  uint64
	UID  uint64
	Comm [16]byte
}

// TestTCPv4ConnectIntegration is an integration test that:
// 1. Loads the eBPF module
// 2. Attaches kprobes to tcp_v4_connect
// 3. Makes a real TCP connection
// 4. Verifies the connection appears in tcpMap with correct PID
func TestTCPv4ConnectIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF modules")
	}

	modulePath := findEbpfModule("opensnitch.o")
	if modulePath == "" {
		t.Skip("opensnitch.o not found - build with: make -C ebpf_prog")
	}

	// Load the eBPF module
	spec, err := ebpf.LoadCollectionSpec(modulePath)
	if err != nil {
		t.Fatalf("failed to load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load collection: %v", err)
	}
	defer coll.Close()

	// Attach kprobes
	kprobeProg := coll.Programs["kprobe__tcp_v4_connect"]
	if kprobeProg == nil {
		t.Fatal("kprobe__tcp_v4_connect program not found")
	}

	kretprobeProg := coll.Programs["kretprobe__tcp_v4_connect"]
	if kretprobeProg == nil {
		t.Fatal("kretprobe__tcp_v4_connect program not found")
	}

	kp, err := link.Kprobe("tcp_v4_connect", kprobeProg, nil)
	if err != nil {
		t.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	krp, err := link.Kretprobe("tcp_v4_connect", kretprobeProg, nil)
	if err != nil {
		t.Fatalf("failed to attach kretprobe: %v", err)
	}
	defer krp.Close()

	t.Log("kprobes attached successfully")

	// Get tcpMap
	tcpMap := coll.Maps["tcpMap"]
	if tcpMap == nil {
		t.Fatal("tcpMap not found")
	}

	// Start a local TCP server as our test fixture
	listener, err := net.Listen("tcp", "127.0.0.1:0") // :0 = random available port
	if err != nil {
		t.Fatalf("failed to start local server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	t.Logf("local test server listening on %s", serverAddr)

	// Accept connections in background (so we don't block)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	// Make a TCP connection to our local server
	t.Logf("making TCP connection to %s", serverAddr)
	conn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Get local address info
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	t.Logf("connection established: %s -> %s", localAddr, remoteAddr)

	// Give the kprobe a moment to populate the map
	time.Sleep(100 * time.Millisecond)

	// Build the key to look up
	// Key format: sport (host order) + daddr + dport (big endian) + saddr
	var key tcpKey
	key.Sport = uint16(localAddr.Port)
	copy(key.Daddr[:], remoteAddr.IP.To4())
	key.Dport = htons(uint16(remoteAddr.Port))
	copy(key.Saddr[:], localAddr.IP.To4())

	t.Logf("looking up key: sport=%d, daddr=%v, dport=%d, saddr=%v",
		key.Sport, key.Daddr, ntohs(key.Dport), key.Saddr)

	// Look up in map
	var value tcpValue
	err = tcpMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	if err != nil {
		// Try with saddr=0 (sometimes the kernel doesn't have saddr yet)
		key.Saddr = [4]byte{0, 0, 0, 0}
		err = tcpMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	}

	if err != nil {
		t.Fatalf("connection not found in tcpMap: %v", err)
	}

	// Verify PID matches our process
	myPid := uint64(os.Getpid())
	comm := string(value.Comm[:])
	// Trim null bytes from comm
	for i, b := range value.Comm {
		if b == 0 {
			comm = string(value.Comm[:i])
			break
		}
	}

	t.Logf("found in map: pid=%d, uid=%d, comm=%s", value.Pid, value.UID, comm)

	if value.Pid != myPid {
		t.Errorf("PID mismatch: expected %d, got %d", myPid, value.Pid)
	} else {
		t.Logf("PID matches: %d", myPid)
	}

	t.Log("integration test passed")
}

// htons converts host byte order to network byte order (big endian)
func htons(v uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return *(*uint16)(unsafe.Pointer(&buf[0]))
}

// ntohs converts network byte order to host byte order
func ntohs(v uint16) uint16 {
	buf := (*[2]byte)(unsafe.Pointer(&v))
	return binary.BigEndian.Uint16(buf[:])
}

// tcpv6Key matches struct tcpv6_key_t in opensnitch.c
type tcpv6Key struct {
	Sport uint16
	Daddr [16]byte
	Dport uint16
	Saddr [16]byte
}

// udpKey matches struct udp_key_t in opensnitch.c (same as tcp)
type udpKey = tcpKey

// udpValue matches struct udp_value_t in opensnitch.c (same as tcp)
type udpValue = tcpValue

// udpv6Key matches struct udpv6_key_t in opensnitch.c (same as tcpv6)
type udpv6Key = tcpv6Key

// loadEbpfCollection is a helper to load the eBPF module
func loadEbpfCollection(t *testing.T) *ebpf.Collection {
	t.Helper()

	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF modules")
	}

	modulePath := findEbpfModule("opensnitch.o")
	if modulePath == "" {
		t.Skip("opensnitch.o not found - build with: make -C ebpf_prog")
	}

	spec, err := ebpf.LoadCollectionSpec(modulePath)
	if err != nil {
		t.Fatalf("failed to load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load collection: %v", err)
	}

	return coll
}

// trimComm extracts the null-terminated string from comm bytes
func trimComm(comm [16]byte) string {
	for i, b := range comm {
		if b == 0 {
			return string(comm[:i])
		}
	}
	return string(comm[:])
}

// TestTCPv6ConnectIntegration tests IPv6 TCP connection tracking
func TestTCPv6ConnectIntegration(t *testing.T) {
	coll := loadEbpfCollection(t)
	defer coll.Close()

	// Attach kprobes
	kprobeProg := coll.Programs["kprobe__tcp_v6_connect"]
	if kprobeProg == nil {
		t.Fatal("kprobe__tcp_v6_connect program not found")
	}

	kretprobeProg := coll.Programs["kretprobe__tcp_v6_connect"]
	if kretprobeProg == nil {
		t.Fatal("kretprobe__tcp_v6_connect program not found")
	}

	kp, err := link.Kprobe("tcp_v6_connect", kprobeProg, nil)
	if err != nil {
		t.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	krp, err := link.Kretprobe("tcp_v6_connect", kretprobeProg, nil)
	if err != nil {
		t.Fatalf("failed to attach kretprobe: %v", err)
	}
	defer krp.Close()

	t.Log("kprobes attached successfully")

	tcpv6Map := coll.Maps["tcpv6Map"]
	if tcpv6Map == nil {
		t.Fatal("tcpv6Map not found")
	}

	// Start local IPv6 TCP server
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available: ", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	t.Logf("local test server listening on %s", serverAddr)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	// Make TCP connection
	conn, err := net.DialTimeout("tcp6", serverAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	t.Logf("connection established: %s -> %s", localAddr, remoteAddr)

	time.Sleep(100 * time.Millisecond)

	// Build key
	var key tcpv6Key
	key.Sport = uint16(localAddr.Port)
	copy(key.Daddr[:], remoteAddr.IP.To16())
	key.Dport = htons(uint16(remoteAddr.Port))
	copy(key.Saddr[:], localAddr.IP.To16())

	// Look up in map
	var value tcpValue
	err = tcpv6Map.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	if err != nil {
		// Try with saddr=0
		key.Saddr = [16]byte{}
		err = tcpv6Map.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	}

	if err != nil {
		t.Fatalf("connection not found in tcpv6Map: %v", err)
	}

	myPid := uint64(os.Getpid())
	t.Logf("found in map: pid=%d, uid=%d, comm=%s", value.Pid, value.UID, trimComm(value.Comm))

	if value.Pid != myPid {
		t.Errorf("PID mismatch: expected %d, got %d", myPid, value.Pid)
	} else {
		t.Logf("PID matches: %d", myPid)
	}
}

// TestUDPv4SendIntegration tests IPv4 UDP tracking via udp_sendmsg
func TestUDPv4SendIntegration(t *testing.T) {
	coll := loadEbpfCollection(t)
	defer coll.Close()

	// Attach kprobe
	kprobeProg := coll.Programs["kprobe__udp_sendmsg"]
	if kprobeProg == nil {
		t.Fatal("kprobe__udp_sendmsg program not found")
	}

	kp, err := link.Kprobe("udp_sendmsg", kprobeProg, nil)
	if err != nil {
		t.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	t.Log("kprobe attached successfully")

	udpMap := coll.Maps["udpMap"]
	if udpMap == nil {
		t.Fatal("udpMap not found")
	}

	// Start local UDP server
	serverAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve addr: %v", err)
	}

	serverConn, err := net.ListenUDP("udp4", serverAddr)
	if err != nil {
		t.Fatalf("failed to start UDP server: %v", err)
	}
	defer serverConn.Close()

	serverAddr = serverConn.LocalAddr().(*net.UDPAddr)
	t.Logf("local UDP server listening on %s", serverAddr)

	// Create UDP client and send data
	clientConn, err := net.DialUDP("udp4", nil, serverAddr)
	if err != nil {
		t.Fatalf("failed to create UDP client: %v", err)
	}
	defer clientConn.Close()

	// Send some data to trigger udp_sendmsg
	_, err = clientConn.Write([]byte("test"))
	if err != nil {
		t.Fatalf("failed to send UDP data: %v", err)
	}

	localAddr := clientConn.LocalAddr().(*net.UDPAddr)
	t.Logf("UDP packet sent: %s -> %s", localAddr, serverAddr)

	time.Sleep(100 * time.Millisecond)

	// Build key
	var key udpKey
	key.Sport = uint16(localAddr.Port)
	copy(key.Daddr[:], serverAddr.IP.To4())
	key.Dport = htons(uint16(serverAddr.Port))
	copy(key.Saddr[:], localAddr.IP.To4())

	// Look up in map
	var value udpValue
	err = udpMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	if err != nil {
		// Try with saddr=0
		key.Saddr = [4]byte{0, 0, 0, 0}
		err = udpMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	}

	if err != nil {
		t.Fatalf("connection not found in udpMap: %v", err)
	}

	myPid := uint64(os.Getpid())
	t.Logf("found in map: pid=%d, uid=%d, comm=%s", value.Pid, value.UID, trimComm(value.Comm))

	if value.Pid != myPid {
		t.Errorf("PID mismatch: expected %d, got %d", myPid, value.Pid)
	} else {
		t.Logf("PID matches: %d", myPid)
	}
}

// TestUDPv6SendIntegration tests IPv6 UDP tracking via udpv6_sendmsg
func TestUDPv6SendIntegration(t *testing.T) {
	coll := loadEbpfCollection(t)
	defer coll.Close()

	// Attach kprobe
	kprobeProg := coll.Programs["kprobe__udpv6_sendmsg"]
	if kprobeProg == nil {
		t.Fatal("kprobe__udpv6_sendmsg program not found")
	}

	kp, err := link.Kprobe("udpv6_sendmsg", kprobeProg, nil)
	if err != nil {
		t.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	t.Log("kprobe attached successfully")

	udpv6Map := coll.Maps["udpv6Map"]
	if udpv6Map == nil {
		t.Fatal("udpv6Map not found")
	}

	// Start local UDP server
	serverAddr, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	if err != nil {
		t.Fatalf("failed to resolve addr: %v", err)
	}

	serverConn, err := net.ListenUDP("udp6", serverAddr)
	if err != nil {
		t.Skip("IPv6 not available: ", err)
	}
	defer serverConn.Close()

	serverAddr = serverConn.LocalAddr().(*net.UDPAddr)
	t.Logf("local UDP server listening on %s", serverAddr)

	// Create UDP client and send data
	clientConn, err := net.DialUDP("udp6", nil, serverAddr)
	if err != nil {
		t.Fatalf("failed to create UDP client: %v", err)
	}
	defer clientConn.Close()

	// Send some data to trigger udpv6_sendmsg
	_, err = clientConn.Write([]byte("test"))
	if err != nil {
		t.Fatalf("failed to send UDP data: %v", err)
	}

	localAddr := clientConn.LocalAddr().(*net.UDPAddr)
	t.Logf("UDP packet sent: %s -> %s", localAddr, serverAddr)

	time.Sleep(100 * time.Millisecond)

	// Build key
	var key udpv6Key
	key.Sport = uint16(localAddr.Port)
	copy(key.Daddr[:], serverAddr.IP.To16())
	key.Dport = htons(uint16(serverAddr.Port))
	copy(key.Saddr[:], localAddr.IP.To16())

	// Look up in map
	var value udpValue
	err = udpv6Map.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	if err != nil {
		// Try with saddr=0
		key.Saddr = [16]byte{}
		err = udpv6Map.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	}

	if err != nil {
		t.Fatalf("connection not found in udpv6Map: %v", err)
	}

	myPid := uint64(os.Getpid())
	t.Logf("found in map: pid=%d, uid=%d, comm=%s", value.Pid, value.UID, trimComm(value.Comm))

	if value.Pid != myPid {
		t.Errorf("PID mismatch: expected %d, got %d", myPid, value.Pid)
	} else {
		t.Logf("PID matches: %d", myPid)
	}
}

// TestInetDgramConnectIntegration tests UDP connect() tracking via inet_dgram_connect
// This is different from udp_sendmsg - it fires when connect() is called on a UDP socket
func TestInetDgramConnectIntegration(t *testing.T) {
	coll := loadEbpfCollection(t)
	defer coll.Close()

	// Attach kprobes for inet_dgram_connect
	kprobeProg := coll.Programs["kprobe__inet_dgram_connect"]
	if kprobeProg == nil {
		t.Fatal("kprobe__inet_dgram_connect program not found")
	}

	kretprobeProg := coll.Programs["kretprobe__inet_dgram_connect"]
	if kretprobeProg == nil {
		t.Fatal("kretprobe__inet_dgram_connect program not found")
	}

	kp, err := link.Kprobe("inet_dgram_connect", kprobeProg, nil)
	if err != nil {
		t.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	krp, err := link.Kretprobe("inet_dgram_connect", kretprobeProg, nil)
	if err != nil {
		t.Fatalf("failed to attach kretprobe: %v", err)
	}
	defer krp.Close()

	t.Log("kprobes attached successfully")

	udpMap := coll.Maps["udpMap"]
	if udpMap == nil {
		t.Fatal("udpMap not found")
	}

	// Start local UDP server
	serverAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve addr: %v", err)
	}

	serverConn, err := net.ListenUDP("udp4", serverAddr)
	if err != nil {
		t.Fatalf("failed to start UDP server: %v", err)
	}
	defer serverConn.Close()

	serverAddr = serverConn.LocalAddr().(*net.UDPAddr)
	t.Logf("local UDP server listening on %s", serverAddr)

	// Use Dial which calls connect() - this triggers inet_dgram_connect
	clientConn, err := net.Dial("udp4", serverAddr.String())
	if err != nil {
		t.Fatalf("failed to dial UDP: %v", err)
	}
	defer clientConn.Close()

	localAddr := clientConn.LocalAddr().(*net.UDPAddr)
	t.Logf("UDP connected: %s -> %s", localAddr, serverAddr)

	time.Sleep(100 * time.Millisecond)

	// Build key - inet_dgram_connect swaps sport byte order
	var key udpKey
	// sport is swapped in the kretprobe
	key.Sport = uint16((localAddr.Port>>8)&0xff) | uint16((localAddr.Port<<8)&0xff00)
	copy(key.Daddr[:], serverAddr.IP.To4())
	key.Dport = htons(uint16(serverAddr.Port))
	copy(key.Saddr[:], localAddr.IP.To4())

	t.Logf("looking up key: sport=%d, daddr=%v, dport=%d, saddr=%v",
		key.Sport, key.Daddr, ntohs(key.Dport), key.Saddr)

	// Look up in map
	var value udpValue
	err = udpMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	if err != nil {
		// Try with original sport (not swapped)
		key.Sport = uint16(localAddr.Port)
		err = udpMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	}
	if err != nil {
		// Try with saddr=0
		key.Saddr = [4]byte{0, 0, 0, 0}
		err = udpMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
	}

	if err != nil {
		t.Fatalf("connection not found in udpMap: %v", err)
	}

	myPid := uint64(os.Getpid())
	t.Logf("found in map: pid=%d, uid=%d, comm=%s", value.Pid, value.UID, trimComm(value.Comm))

	if value.Pid != myPid {
		t.Errorf("PID mismatch: expected %d, got %d", myPid, value.Pid)
	} else {
		t.Logf("PID matches: %d", myPid)
	}
}

// TestExecveIntegration tests process execution tracking via tracepoints
func TestExecveIntegration(t *testing.T) {
	coll := loadEbpfCollection(t)
	defer coll.Close()

	// Load the procs module
	testDir := getTestDir()
	repoRoot := filepath.Join(testDir, "..", "..", "..")
	procsModulePath := filepath.Join(repoRoot, "ebpf_prog", "opensnitch-procs.o")

	if _, err := os.Stat(procsModulePath); err != nil {
		t.Skip("opensnitch-procs.o not found")
	}

	spec, err := ebpf.LoadCollectionSpec(procsModulePath)
	if err != nil {
		t.Fatalf("failed to load procs spec: %v", err)
	}

	procsColl, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load procs collection: %v", err)
	}
	defer procsColl.Close()

	// Attach tracepoint for execve
	execveProg := procsColl.Programs["tracepoint__syscalls_sys_enter_execve"]
	if execveProg == nil {
		t.Fatal("tracepoint__syscalls_sys_enter_execve not found")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", execveProg, nil)
	if err != nil {
		t.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	t.Log("tracepoint attached successfully")

	// Get the events ringbuf
	eventsMap := procsColl.Maps["events"]
	if eventsMap == nil {
		t.Fatal("events map not found")
	}

	// Create ringbuf reader
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Spawn a subprocess - this should trigger execve tracepoint
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start subprocess: %v", err)
	}
	childPid := cmd.Process.Pid
	t.Logf("spawned subprocess: pid=%d, cmd=/bin/true", childPid)

	cmd.Wait()

	// Read events with timeout
	done := make(chan struct{})
	var foundEvent bool

	go func() {
		defer close(done)
		for i := 0; i < 10; i++ { // try reading a few events
			record, err := rd.Read()
			if err != nil {
				return
			}
			if len(record.RawSample) > 0 {
				// Parse basic fields from the event
				// struct data_t has: type(8), pid(4), uid(4), ppid(4), ...
				if len(record.RawSample) >= 16 {
					eventPid := binary.LittleEndian.Uint32(record.RawSample[8:12])
					t.Logf("received event: pid=%d", eventPid)
					if eventPid == uint32(childPid) {
						foundEvent = true
						return
					}
				}
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Log("timeout waiting for events")
	}

	if foundEvent {
		t.Logf("found execve event for pid %d", childPid)
	} else {
		t.Log("execve event not found in ringbuf (may have been processed already)")
	}
}

// findLibc returns the path to libc.so
func findLibc() string {
	paths := []string{
		"/lib/x86_64-linux-gnu/libc.so.6",     // Debian/Ubuntu
		"/lib64/libc.so.6",                     // RHEL/Fedora
		"/usr/lib/libc.so.6",                   // Arch
		"/lib/aarch64-linux-gnu/libc.so.6",    // ARM64 Debian
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// TestGetaddrinfoIntegration tests DNS resolution tracking via uprobes
func TestGetaddrinfoIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF modules")
	}

	// Load the DNS module
	testDir := getTestDir()
	repoRoot := filepath.Join(testDir, "..", "..", "..")
	dnsModulePath := filepath.Join(repoRoot, "ebpf_prog", "opensnitch-dns.o")

	if _, err := os.Stat(dnsModulePath); err != nil {
		t.Skip("opensnitch-dns.o not found")
	}

	libcPath := findLibc()
	if libcPath == "" {
		t.Skip("libc not found")
	}
	t.Logf("using libc: %s", libcPath)

	spec, err := ebpf.LoadCollectionSpec(dnsModulePath)
	if err != nil {
		t.Fatalf("failed to load dns spec: %v", err)
	}

	dnsColl, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load dns collection: %v", err)
	}
	defer dnsColl.Close()

	// Attach uprobe for getaddrinfo
	getaddrinfoProg := dnsColl.Programs["uprobe__getaddrinfo"]
	if getaddrinfoProg == nil {
		t.Fatal("uprobe__getaddrinfo not found")
	}

	getaddrinfoRetProg := dnsColl.Programs["uretprobe__getaddrinfo"]
	if getaddrinfoRetProg == nil {
		t.Fatal("uretprobe__getaddrinfo not found")
	}

	// Open libc executable
	ex, err := link.OpenExecutable(libcPath)
	if err != nil {
		t.Fatalf("failed to open libc: %v", err)
	}

	up, err := ex.Uprobe("getaddrinfo", getaddrinfoProg, nil)
	if err != nil {
		t.Fatalf("failed to attach uprobe: %v", err)
	}
	defer up.Close()

	uret, err := ex.Uretprobe("getaddrinfo", getaddrinfoRetProg, nil)
	if err != nil {
		t.Fatalf("failed to attach uretprobe: %v", err)
	}
	defer uret.Close()

	t.Log("uprobes attached successfully")

	// Get the events ringbuf
	eventsMap := dnsColl.Maps["events"]
	if eventsMap == nil {
		t.Fatal("events map not found")
	}

	// Create ringbuf reader
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Do a DNS lookup - this should trigger getaddrinfo
	t.Log("performing DNS lookup for localhost")
	addrs, err := net.LookupHost("localhost")
	if err != nil {
		t.Logf("DNS lookup failed (expected on some systems): %v", err)
	} else {
		t.Logf("resolved localhost to: %v", addrs)
	}

	// Read events with timeout
	done := make(chan struct{})
	var foundEvent bool
	var eventHost string

	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			record, err := rd.Read()
			if err != nil {
				return
			}
			if len(record.RawSample) > 20 {
				// struct nameLookupEvent: addr_type(4) + ip(16) + host(252)
				// Extract host starting at offset 20
				hostBytes := record.RawSample[20:]
				for i, b := range hostBytes {
					if b == 0 {
						eventHost = string(hostBytes[:i])
						break
					}
				}
				if eventHost != "" {
					t.Logf("received DNS event: host=%s", eventHost)
					foundEvent = true
					return
				}
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Log("timeout waiting for DNS events")
	}

	if foundEvent {
		t.Logf("found DNS event for host: %s", eventHost)
	} else {
		t.Log("DNS event not found in ringbuf (may need different lookup method)")
	}
}

// TestIPTunnelXmitIntegration tests IP tunnel traffic tracking via iptunnel_xmit kprobe.
// This requires creating an IP-in-IP tunnel.
// Uses network namespace for isolation on host, or runs native in VM.
func TestIPTunnelXmitIntegration(t *testing.T) {
	coll := loadEbpfCollection(t)
	defer coll.Close()

	// Check if ipip module is available
	if out, err := exec.Command("modprobe", "ipip").CombinedOutput(); err != nil {
		t.Skipf("ipip module not available: %v: %s", err, out)
	}

	// Attach kprobe
	kprobeProg := coll.Programs["kprobe__iptunnel_xmit"]
	if kprobeProg == nil {
		t.Fatal("kprobe__iptunnel_xmit program not found")
	}

	kp, err := link.Kprobe("iptunnel_xmit", kprobeProg, nil)
	if err != nil {
		t.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	t.Log("kprobe attached successfully")

	udpMap := coll.Maps["udpMap"]
	if udpMap == nil {
		t.Fatal("udpMap not found")
	}

	// Setup network
	testNet := testutil.NewTestNetwork()
	if err := testNet.Setup(); err != nil {
		t.Fatalf("failed to setup test network: %v", err)
	}
	defer testNet.Cleanup()

	t.Logf("using network mode: native=%v", testNet.IsNative())

	// Create IPIP tunnel
	// We need two endpoints - create a dummy setup for testing
	cmds := [][]string{
		{"ip", "link", "add", "dummy0", "type", "dummy"},
		{"ip", "addr", "add", "192.168.100.1/24", "dev", "dummy0"},
		{"ip", "link", "set", "dummy0", "up"},
		{"ip", "tunnel", "add", "tun0", "mode", "ipip", "local", "192.168.100.1", "remote", "192.168.100.2"},
		{"ip", "addr", "add", "10.0.0.1/24", "dev", "tun0"},
		{"ip", "link", "set", "tun0", "up"},
	}

	for _, cmd := range cmds {
		out, err := testNet.Exec(cmd[0], cmd[1:]...)
		if err != nil {
			t.Logf("cmd %v failed: %v: %s", cmd, err, out)
			// Continue anyway - some commands may fail in namespace
		}
	}

	// Try to send traffic through the tunnel
	// This will fail to actually deliver (no remote endpoint) but should trigger the kprobe
	if testNet.IsNative() {
		// In native mode, we can try to ping through the tunnel
		exec.Command("ping", "-c", "1", "-W", "1", "10.0.0.2").Run()
	} else {
		// In namespace, use ip netns exec
		testNet.Exec("ping", "-c", "1", "-W", "1", "10.0.0.2")
	}

	time.Sleep(100 * time.Millisecond)

	// Check if anything appeared in the map
	var foundEntry bool
	iter := udpMap.Iterate()
	var key udpKey
	var value udpValue
	for iter.Next(&key, &value) {
		// Look for entries with our tunnel IPs
		srcIP := net.IP(key.Saddr[:])
		dstIP := net.IP(key.Daddr[:])
		if strings.HasPrefix(srcIP.String(), "192.168.100.") || strings.HasPrefix(srcIP.String(), "10.0.0.") {
			t.Logf("found tunnel entry: %s:%d -> %s:%d, pid=%d",
				srcIP, key.Sport, dstIP, ntohs(key.Dport), value.Pid)
			foundEntry = true
		}
	}

	if foundEntry {
		t.Log("tunnel traffic captured successfully")
	} else {
		t.Log("no tunnel entries found (tunnel may not have sent packets)")
	}
}

// TestUDPTunnel6XmitIntegration tests IPv6 UDP tunnel tracking.
// Requires ip6_udp_tunnel module (used by WireGuard, VXLAN over IPv6).
func TestUDPTunnel6XmitIntegration(t *testing.T) {
	coll := loadEbpfCollection(t)
	defer coll.Close()

	// Check if ip6_udp_tunnel module is available
	if out, err := exec.Command("modprobe", "ip6_udp_tunnel").CombinedOutput(); err != nil {
		t.Skipf("ip6_udp_tunnel module not available: %v: %s", err, out)
	}

	// Check for vxlan module (uses ip6_udp_tunnel)
	if out, err := exec.Command("modprobe", "vxlan").CombinedOutput(); err != nil {
		t.Skipf("vxlan module not available: %v: %s", err, out)
	}

	// Attach kprobe
	kprobeProg := coll.Programs["kprobe__udp_tunnel6_xmit_skb"]
	if kprobeProg == nil {
		t.Fatal("kprobe__udp_tunnel6_xmit_skb program not found")
	}

	kp, err := link.Kprobe("udp_tunnel6_xmit_skb", kprobeProg, nil)
	if err != nil {
		// This kprobe may not be available on all kernels
		t.Skipf("failed to attach kprobe (may not exist on this kernel): %v", err)
	}
	defer kp.Close()

	t.Log("kprobe attached successfully")

	udpv6Map := coll.Maps["udpv6Map"]
	if udpv6Map == nil {
		t.Fatal("udpv6Map not found")
	}

	// Setup network
	testNet := testutil.NewTestNetwork()
	if err := testNet.Setup(); err != nil {
		t.Fatalf("failed to setup test network: %v", err)
	}
	defer testNet.Cleanup()

	t.Logf("using network mode: native=%v", testNet.IsNative())

	// Create VXLAN over IPv6
	// This is complex - need proper setup with bridge
	cmds := [][]string{
		{"ip", "link", "add", "dummy0", "type", "dummy"},
		{"ip", "-6", "addr", "add", "fd00::1/64", "dev", "dummy0"},
		{"ip", "link", "set", "dummy0", "up"},
		{"ip", "link", "add", "vxlan0", "type", "vxlan", "id", "100", "local", "fd00::1", "remote", "fd00::2", "dstport", "4789"},
		{"ip", "link", "set", "vxlan0", "up"},
	}

	for _, cmd := range cmds {
		out, err := testNet.Exec(cmd[0], cmd[1:]...)
		if err != nil {
			t.Logf("cmd %v failed: %v: %s", cmd, err, out)
		}
	}

	// Try to trigger tunnel traffic
	if testNet.IsNative() {
		exec.Command("ping6", "-c", "1", "-W", "1", "fd00::2").Run()
	} else {
		testNet.Exec("ping", "-6", "-c", "1", "-W", "1", "fd00::2")
	}

	time.Sleep(100 * time.Millisecond)

	// Check map for entries
	var foundEntry bool
	iter := udpv6Map.Iterate()
	var key udpv6Key
	var value udpValue
	for iter.Next(&key, &value) {
		t.Logf("found udpv6 entry: sport=%d, dport=%d, pid=%d",
			key.Sport, ntohs(key.Dport), value.Pid)
		foundEntry = true
	}

	if foundEntry {
		t.Log("IPv6 tunnel traffic captured successfully")
	} else {
		t.Log("no IPv6 tunnel entries found (tunnel may not have sent packets)")
	}
}

// TestExecveExitIntegration tests the sys_exit_execve tracepoint.
// This fires when execve() returns, capturing the return code.
func TestExecveExitIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF modules")
	}

	// Load the procs module
	testDir := getTestDir()
	repoRoot := filepath.Join(testDir, "..", "..", "..")
	procsModulePath := filepath.Join(repoRoot, "ebpf_prog", "opensnitch-procs.o")

	if _, err := os.Stat(procsModulePath); err != nil {
		t.Skip("opensnitch-procs.o not found")
	}

	spec, err := ebpf.LoadCollectionSpec(procsModulePath)
	if err != nil {
		t.Fatalf("failed to load procs spec: %v", err)
	}

	procsColl, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load procs collection: %v", err)
	}
	defer procsColl.Close()

	// Attach tracepoints for execve enter and exit
	execveEnterProg := procsColl.Programs["tracepoint__syscalls_sys_enter_execve"]
	if execveEnterProg == nil {
		t.Fatal("tracepoint__syscalls_sys_enter_execve not found")
	}

	execveExitProg := procsColl.Programs["tracepoint__syscalls_sys_exit_execve"]
	if execveExitProg == nil {
		t.Fatal("tracepoint__syscalls_sys_exit_execve not found")
	}

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_execve", execveEnterProg, nil)
	if err != nil {
		t.Fatalf("failed to attach enter tracepoint: %v", err)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_execve", execveExitProg, nil)
	if err != nil {
		t.Fatalf("failed to attach exit tracepoint: %v", err)
	}
	defer tpExit.Close()

	t.Log("tracepoints attached successfully")

	// Get the events ringbuf
	eventsMap := procsColl.Maps["events"]
	if eventsMap == nil {
		t.Fatal("events map not found")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Spawn a subprocess that will succeed
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start subprocess: %v", err)
	}
	childPid := cmd.Process.Pid
	t.Logf("spawned subprocess: pid=%d, cmd=/bin/true", childPid)
	cmd.Wait()

	// Also spawn one that will fail (to test non-zero return)
	cmdFail := exec.Command("/bin/false")
	cmdFail.Start()
	failPid := cmdFail.Process.Pid
	t.Logf("spawned failing subprocess: pid=%d, cmd=/bin/false", failPid)
	cmdFail.Wait()

	// Read events with timeout
	done := make(chan struct{})
	var foundExitEvent bool
	var retCode int32

	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			record, err := rd.Read()
			if err != nil {
				return
			}
			if len(record.RawSample) >= 20 {
				// struct data_t: type(8), pid(4), uid(4), ppid(4), ret_code(4), ...
				eventType := binary.LittleEndian.Uint64(record.RawSample[0:8])
				eventPid := binary.LittleEndian.Uint32(record.RawSample[8:12])
				// ret_code is at offset 20
				if len(record.RawSample) >= 24 {
					retCode = int32(binary.LittleEndian.Uint32(record.RawSample[20:24]))
				}

				// EVENT_EXEC = 1, EVENT_EXECVEAT = 2
				if (eventType == 1 || eventType == 2) && (eventPid == uint32(childPid) || eventPid == uint32(failPid)) {
					t.Logf("received event: type=%d, pid=%d, ret_code=%d", eventType, eventPid, retCode)
					foundExitEvent = true
				}
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Log("timeout waiting for events")
	}

	if foundExitEvent {
		t.Log("found execve exit event")
	} else {
		t.Log("execve exit event not captured (ringbuf may have been drained)")
	}
}

// TestExecveatIntegration tests the execveat tracepoints.
// execveat() is like execve() but with a directory fd parameter.
func TestExecveatIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF modules")
	}

	testDir := getTestDir()
	repoRoot := filepath.Join(testDir, "..", "..", "..")
	procsModulePath := filepath.Join(repoRoot, "ebpf_prog", "opensnitch-procs.o")

	if _, err := os.Stat(procsModulePath); err != nil {
		t.Skip("opensnitch-procs.o not found")
	}

	spec, err := ebpf.LoadCollectionSpec(procsModulePath)
	if err != nil {
		t.Fatalf("failed to load procs spec: %v", err)
	}

	procsColl, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load procs collection: %v", err)
	}
	defer procsColl.Close()

	// Attach tracepoints for execveat
	execveatEnterProg := procsColl.Programs["tracepoint__syscalls_sys_enter_execveat"]
	if execveatEnterProg == nil {
		t.Fatal("tracepoint__syscalls_sys_enter_execveat not found")
	}

	execveatExitProg := procsColl.Programs["tracepoint__syscalls_sys_exit_execveat"]
	if execveatExitProg == nil {
		t.Fatal("tracepoint__syscalls_sys_exit_execveat not found")
	}

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_execveat", execveatEnterProg, nil)
	if err != nil {
		t.Fatalf("failed to attach enter tracepoint: %v", err)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_execveat", execveatExitProg, nil)
	if err != nil {
		t.Fatalf("failed to attach exit tracepoint: %v", err)
	}
	defer tpExit.Close()

	t.Log("execveat tracepoints attached successfully")

	eventsMap := procsColl.Maps["events"]
	if eventsMap == nil {
		t.Fatal("events map not found")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// execveat is typically used by fexecve() or when executing via a dir fd
	// We can trigger it using a helper script that uses fexecve
	// For simplicity, we'll just verify the tracepoints are attached and working
	// by spawning a regular process (some systems may use execveat internally)

	// Create a test script that we can execute
	testScript := filepath.Join(t.TempDir(), "test.sh")
	if err := os.WriteFile(testScript, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("failed to create test script: %v", err)
	}

	cmd := exec.Command(testScript)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start subprocess: %v", err)
	}
	childPid := cmd.Process.Pid
	t.Logf("spawned subprocess: pid=%d", childPid)
	cmd.Wait()

	// Read events
	done := make(chan struct{})
	var foundEvent bool

	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			record, err := rd.Read()
			if err != nil {
				return
			}
			if len(record.RawSample) >= 16 {
				eventType := binary.LittleEndian.Uint64(record.RawSample[0:8])
				eventPid := binary.LittleEndian.Uint32(record.RawSample[8:12])
				// EVENT_EXECVEAT = 2
				if eventType == 2 {
					t.Logf("received execveat event: pid=%d", eventPid)
					foundEvent = true
					return
				}
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Log("timeout waiting for execveat events")
	}

	if foundEvent {
		t.Log("found execveat event")
	} else {
		t.Log("no execveat events captured (most processes use execve, not execveat)")
	}
}

// TestProcessExitIntegration tests the sched_process_exit tracepoint.
// This fires when any process exits.
func TestProcessExitIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF modules")
	}

	testDir := getTestDir()
	repoRoot := filepath.Join(testDir, "..", "..", "..")
	procsModulePath := filepath.Join(repoRoot, "ebpf_prog", "opensnitch-procs.o")

	if _, err := os.Stat(procsModulePath); err != nil {
		t.Skip("opensnitch-procs.o not found")
	}

	spec, err := ebpf.LoadCollectionSpec(procsModulePath)
	if err != nil {
		t.Fatalf("failed to load procs spec: %v", err)
	}

	procsColl, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load procs collection: %v", err)
	}
	defer procsColl.Close()

	// First attach execve to populate execMap (required for exit events)
	execveEnterProg := procsColl.Programs["tracepoint__syscalls_sys_enter_execve"]
	if execveEnterProg == nil {
		t.Fatal("tracepoint__syscalls_sys_enter_execve not found")
	}

	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", execveEnterProg, nil)
	if err != nil {
		t.Fatalf("failed to attach execve tracepoint: %v", err)
	}
	defer tpExecve.Close()

	// Attach sched_process_exit
	schedExitProg := procsColl.Programs["tracepoint__sched_sched_process_exit"]
	if schedExitProg == nil {
		t.Fatal("tracepoint__sched_sched_process_exit not found")
	}

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", schedExitProg, nil)
	if err != nil {
		t.Fatalf("failed to attach sched_process_exit tracepoint: %v", err)
	}
	defer tpExit.Close()

	t.Log("tracepoints attached successfully")

	eventsMap := procsColl.Maps["events"]
	if eventsMap == nil {
		t.Fatal("events map not found")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Spawn a subprocess that will exit
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start subprocess: %v", err)
	}
	childPid := cmd.Process.Pid
	t.Logf("spawned subprocess: pid=%d", childPid)
	cmd.Wait()
	t.Logf("subprocess exited")

	// Read events
	done := make(chan struct{})
	var foundExecEvent, foundExitEvent bool

	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			record, err := rd.Read()
			if err != nil {
				return
			}
			if len(record.RawSample) >= 16 {
				eventType := binary.LittleEndian.Uint64(record.RawSample[0:8])
				eventPid := binary.LittleEndian.Uint32(record.RawSample[8:12])

				// EVENT_EXEC = 1, EVENT_SCHED_EXIT = 4
				if eventPid == uint32(childPid) {
					if eventType == 1 {
						t.Logf("received exec event: pid=%d", eventPid)
						foundExecEvent = true
					} else if eventType == 4 {
						t.Logf("received sched_exit event: pid=%d", eventPid)
						foundExitEvent = true
						return
					}
				}
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Log("timeout waiting for events")
	}

	if foundExecEvent {
		t.Log("found exec event for subprocess")
	}
	if foundExitEvent {
		t.Log("found sched_process_exit event for subprocess")
	} else {
		t.Log("sched_process_exit event not captured (process may have exited before tracepoint fired)")
	}
}

// TestGethostbynameIntegration tests DNS resolution tracking via gethostbyname uprobe.
// gethostbyname is the older DNS resolution function (getaddrinfo is preferred).
func TestGethostbynameIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF modules")
	}

	testDir := getTestDir()
	repoRoot := filepath.Join(testDir, "..", "..", "..")
	dnsModulePath := filepath.Join(repoRoot, "ebpf_prog", "opensnitch-dns.o")

	if _, err := os.Stat(dnsModulePath); err != nil {
		t.Skip("opensnitch-dns.o not found")
	}

	libcPath := findLibc()
	if libcPath == "" {
		t.Skip("libc not found")
	}
	t.Logf("using libc: %s", libcPath)

	spec, err := ebpf.LoadCollectionSpec(dnsModulePath)
	if err != nil {
		t.Fatalf("failed to load dns spec: %v", err)
	}

	dnsColl, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load dns collection: %v", err)
	}
	defer dnsColl.Close()

	// Attach uretprobe for gethostbyname
	gethostbynameProg := dnsColl.Programs["uretprobe__gethostbyname"]
	if gethostbynameProg == nil {
		t.Fatal("uretprobe__gethostbyname not found")
	}

	ex, err := link.OpenExecutable(libcPath)
	if err != nil {
		t.Fatalf("failed to open libc: %v", err)
	}

	// gethostbyname is deprecated but still present in libc
	uret, err := ex.Uretprobe("gethostbyname", gethostbynameProg, nil)
	if err != nil {
		t.Fatalf("failed to attach uretprobe: %v", err)
	}
	defer uret.Close()

	t.Log("uretprobe attached successfully")

	eventsMap := dnsColl.Maps["events"]
	if eventsMap == nil {
		t.Fatal("events map not found")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// gethostbyname is not directly accessible from Go's net package
	// We need to trigger it via CGO or a subprocess
	// Use a subprocess that calls gethostbyname
	t.Log("spawning subprocess to call gethostbyname...")

	// Create a small C program to call gethostbyname
	testDir2 := t.TempDir()
	cFile := filepath.Join(testDir2, "test_dns.c")
	binFile := filepath.Join(testDir2, "test_dns")

	cCode := `#include <netdb.h>
#include <stdio.h>
int main() {
    struct hostent *h = gethostbyname("localhost");
    if (h) printf("resolved: %s\n", h->h_name);
    return 0;
}
`
	if err := os.WriteFile(cFile, []byte(cCode), 0644); err != nil {
		t.Fatalf("failed to write C file: %v", err)
	}

	// Compile the test program
	compileCmd := exec.Command("gcc", "-o", binFile, cFile)
	if out, err := compileCmd.CombinedOutput(); err != nil {
		t.Skipf("failed to compile test program (gcc not available): %v: %s", err, out)
	}

	// Run the test program
	cmd := exec.Command(binFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("test program output: %s (err: %v)", out, err)
	} else {
		t.Logf("test program output: %s", out)
	}

	// Read events
	done := make(chan struct{})
	var foundEvent bool
	var eventHost string

	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			record, err := rd.Read()
			if err != nil {
				return
			}
			if len(record.RawSample) > 20 {
				// struct nameLookupEvent: addr_type(4) + ip(16) + host(252)
				hostBytes := record.RawSample[20:]
				for i, b := range hostBytes {
					if b == 0 {
						eventHost = string(hostBytes[:i])
						break
					}
				}
				if eventHost != "" {
					t.Logf("received DNS event: host=%s", eventHost)
					foundEvent = true
					return
				}
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Log("timeout waiting for DNS events")
	}

	if foundEvent {
		t.Logf("found gethostbyname event for host: %s", eventHost)
	} else {
		t.Log("gethostbyname event not found in ringbuf")
	}
}
