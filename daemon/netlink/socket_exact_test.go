package netlink

import (
	"errors"
	"net"
	"reflect"
	"runtime"
	"syscall"
	"testing"
)

// These tests use loopback sockets only. They run by default (unlike the
// NETLINK_TESTS-gated ones) and skip if the environment has no usable
// loopback or sock_diag.
func unavailable(t *testing.T, err error) {
	t.Helper()
	t.Skip(err)
}

type tuple struct {
	src, dst     net.IP
	sport, dport uint
}

func tupleOf(local, remote net.Addr) tuple {
	l, r := local.(*net.TCPAddr), remote.(*net.TCPAddr)
	return tuple{l.IP, r.IP, uint(l.Port), uint(r.Port)}
}

// connectTCP returns a connected TCP tuple over loopback addr ("127.0.0.1" or "::1").
func connectTCP(t *testing.T, network, addr string) tuple {
	t.Helper()
	l, err := net.Listen(network, net.JoinHostPort(addr, "0"))
	if err != nil {
		unavailable(t, err)
	}
	t.Cleanup(func() { l.Close() })
	c, err := net.Dial(network, l.Addr().String())
	if err != nil {
		unavailable(t, err)
	}
	t.Cleanup(func() { c.Close() })
	return tupleOf(c.LocalAddr(), c.RemoteAddr())
}

// countExact counts the exact lookups and returns the real results.
func countExact(t *testing.T) *int {
	t.Helper()
	calls := 0
	t.Cleanup(func() { socketGetExact = SocketGetExact })
	socketGetExact = func(family, proto uint8, srcPort, dstPort uint16, local, remote net.IP) (*Socket, error) {
		calls++
		return SocketGetExact(family, proto, srcPort, dstPort, local, remote)
	}
	return &calls
}

func family(proto string) uint8 {
	if proto[len(proto)-1] == '6' {
		return syscall.AF_INET6
	}
	return syscall.AF_INET
}

// dumpRecord returns the dumped socket with this inode.
func dumpRecord(t *testing.T, fam, ipproto uint8, c tuple, inode int) *Socket {
	t.Helper()
	list, err := SocketGet(fam, ipproto, uint16(c.sport), uint16(c.dport), c.src, c.dst)
	if err != nil {
		unavailable(t, err)
	}
	for _, s := range list {
		if s != nil && int(s.INode) == inode {
			return s
		}
	}
	t.Fatalf("inode %d not in the dump of port %d", inode, c.sport)
	return nil
}

func TestExactTCPLookupMatchesDump(t *testing.T) {
	for _, tc := range []struct{ proto, network, addr string }{
		{"tcp", "tcp4", "127.0.0.1"},
		{"tcp6", "tcp6", "::1"},
	} {
		t.Run(tc.proto, func(t *testing.T) {
			c := connectTCP(t, tc.network, tc.addr)
			calls := countExact(t)
			uid, inodes := GetSocketInfo(tc.proto, c.src, c.sport, c.dst, c.dport)
			if *calls != 1 {
				t.Fatalf("exact lookup calls = %d, want 1", *calls)
			}
			sock := exactTCPSocket(family(tc.proto), syscall.IPPROTO_TCP, c.src, c.sport, c.dst, c.dport)
			if sock == nil {
				t.Fatal("exact lookup missed a connected socket; GetSocketInfo used the dump")
			}
			dumpUID, dumpInodes := socketInfoFromDump(family(tc.proto), syscall.IPPROTO_TCP, c.src, c.sport, c.dst, c.dport)
			if len(inodes) != 1 || !reflect.DeepEqual(inodes, dumpInodes) {
				t.Fatalf("inodes: exact %v, dump %v", inodes, dumpInodes)
			}
			if rec := dumpRecord(t, family(tc.proto), syscall.IPPROTO_TCP, c, inodes[0]); rec.UID != sock.UID {
				t.Fatalf("uid: exact %d, dump record %d", sock.UID, rec.UID)
			}
			// Only this socket uses the ephemeral port, so the uids agree too.
			if uid != dumpUID {
				t.Fatalf("uid: exact %d, dump %d", uid, dumpUID)
			}
		})
	}
}

func TestExactTCPLookupFallsBackToDump(t *testing.T) {
	c := connectTCP(t, "tcp4", "127.0.0.1")
	_, want := socketInfoFromDump(syscall.AF_INET, syscall.IPPROTO_TCP, c.src, c.sport, c.dst, c.dport)
	if len(want) != 1 {
		t.Fatalf("dump inodes %v", want)
	}

	t.Run("lookup error", func(t *testing.T) {
		t.Cleanup(func() { socketGetExact = SocketGetExact })
		socketGetExact = func(uint8, uint8, uint16, uint16, net.IP, net.IP) (*Socket, error) {
			return nil, errors.New("forced")
		}
		if _, got := GetSocketInfo("tcp", c.src, c.sport, c.dst, c.dport); !reflect.DeepEqual(got, want) {
			t.Fatalf("inodes %v, want dump %v", got, want)
		}
	})
	t.Run("different tuple", func(t *testing.T) {
		t.Cleanup(func() { socketGetExact = SocketGetExact })
		socketGetExact = func(family, proto uint8, srcPort, dstPort uint16, local, remote net.IP) (*Socket, error) {
			s, err := SocketGetExact(family, proto, srcPort, dstPort, local, remote)
			if s != nil { // another connection's socket
				s.ID.DestinationPort++
				s.INode++
			}
			return s, err
		}
		if _, got := GetSocketInfo("tcp", c.src, c.sport, c.dst, c.dport); !reflect.DeepEqual(got, want) {
			t.Fatalf("inodes %v, want dump %v", got, want)
		}
	})
	t.Run("nonexistent tuple", func(t *testing.T) {
		calls := countExact(t)
		missing := c.dport + 1
		if s := exactTCPSocket(syscall.AF_INET, syscall.IPPROTO_TCP, c.src, c.sport, c.dst, missing); s != nil {
			t.Fatalf("exact lookup found a socket for a closed port: %+v", s.ID)
		}
		uid, got := GetSocketInfo("tcp", c.src, c.sport, c.dst, missing)
		dumpUID, dump := socketInfoFromDump(syscall.AF_INET, syscall.IPPROTO_TCP, c.src, c.sport, c.dst, missing)
		if *calls != 2 || uid != dumpUID || !reflect.DeepEqual(got, dump) {
			t.Fatalf("calls %d, got %d %v, dump %d %v", *calls, uid, got, dumpUID, dump)
		}
	})
}

// A dual-stack AF_INET6 socket connected to an IPv4 address is listed by
// neither the AF_INET dump nor, after the family check, the exact lookup.
func TestExactTCPLookupKeepsFamily(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		unavailable(t, err)
	}
	defer l.Close()
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		unavailable(t, err)
	}
	defer syscall.Close(fd)
	mapped := [16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1}
	if err := syscall.Connect(fd, &syscall.SockaddrInet6{Port: l.Addr().(*net.TCPAddr).Port, Addr: mapped}); err != nil {
		unavailable(t, err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	c := tuple{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1), uint(sa.(*syscall.SockaddrInet6).Port), uint(l.Addr().(*net.TCPAddr).Port)}
	uid, got := GetSocketInfo("tcp", c.src, c.sport, c.dst, c.dport)
	dumpUID, dump := socketInfoFromDump(syscall.AF_INET, syscall.IPPROTO_TCP, c.src, c.sport, c.dst, c.dport)
	if uid != dumpUID || !reflect.DeepEqual(got, dump) {
		t.Fatalf("got %d %v, dump %d %v", uid, got, dumpUID, dump)
	}
}

// UDP and wildcard, broadcast or multicast destinations keep the dump path.
func TestExactTCPLookupNotUsed(t *testing.T) {
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		unavailable(t, err)
	}
	defer u.Close()
	uc, err := net.DialUDP("udp4", nil, u.LocalAddr().(*net.UDPAddr))
	if err != nil {
		unavailable(t, err)
	}
	defer uc.Close()
	la, ra := uc.LocalAddr().(*net.UDPAddr), uc.RemoteAddr().(*net.UDPAddr)
	c := connectTCP(t, "tcp4", "127.0.0.1")

	for _, tc := range []struct {
		name, proto string
		c           tuple
	}{
		{"udp", "udp", tuple{la.IP, ra.IP, uint(la.Port), uint(ra.Port)}},
		{"wildcard", "tcp", tuple{c.src, net.IPv4zero, c.sport, c.dport}},
		{"broadcast", "tcp", tuple{c.src, net.IPv4bcast, c.sport, c.dport}},
		{"multicast", "tcp", tuple{c.src, net.IPv4(239, 255, 255, 250), c.sport, 1900}},
		{"no port", "tcp", tuple{c.src, c.dst, c.sport, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := countExact(t)
			ipproto := uint8(syscall.IPPROTO_TCP)
			if tc.proto == "udp" {
				ipproto = syscall.IPPROTO_UDP
			}
			uid, got := GetSocketInfo(tc.proto, tc.c.src, tc.c.sport, tc.c.dst, tc.c.dport)
			dumpUID, dump := socketInfoFromDump(syscall.AF_INET, ipproto, tc.c.src, tc.c.sport, tc.c.dst, tc.c.dport)
			if *calls != 0 {
				t.Fatalf("exact lookup used %d times", *calls)
			}
			if uid != dumpUID || !reflect.DeepEqual(got, dump) {
				t.Fatalf("got %d %v, dump %d %v", uid, got, dumpUID, dump)
			}
			if tc.proto == "udp" && len(got) != 1 {
				t.Fatalf("connected UDP socket not found by the dump: %v", got)
			}
		})
	}
}

// sharedPortSocket creates a TCP socket bound (SO_REUSEADDR) to bindIP:port
// and connected to dst, and returns its fd, the bound port and its inode. With
// asUID >= 0 the socket is created by a thread whose uid was switched with a
// raw setresuid (only that thread, which exits afterwards), so the kernel
// records that uid as the socket owner; ok is false if the switch is refused.
func sharedPortSocket(t *testing.T, asUID int, bindIP net.IP, port int, dst *net.TCPAddr) (fd, boundPort, inode int, ok bool) {
	t.Helper()
	type result struct {
		fd, port, inode int
		err             error
	}
	create := func() (r result) {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return result{err: err}
		}
		fail := func(err error) result { syscall.Close(fd); return result{err: err} }
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			return fail(err)
		}
		var b, d [4]byte
		copy(b[:], bindIP.To4())
		copy(d[:], dst.IP.To4())
		if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: port, Addr: b}); err != nil {
			return fail(err)
		}
		if err := syscall.Connect(fd, &syscall.SockaddrInet4{Port: dst.Port, Addr: d}); err != nil {
			return fail(err)
		}
		sa, err := syscall.Getsockname(fd)
		if err != nil {
			return fail(err)
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			return fail(err)
		}
		return result{fd, sa.(*syscall.SockaddrInet4).Port, int(st.Ino), nil}
	}
	var r result
	if asUID < 0 {
		r = create()
	} else {
		done := make(chan result, 1)
		go func() {
			// The goroutine exits while locked, which ends its thread.
			runtime.LockOSThread()
			u := uintptr(asUID)
			if _, _, errno := syscall.RawSyscall(syscall.SYS_SETRESUID, u, u, u); errno != 0 {
				done <- result{err: errno}
				return
			}
			done <- create()
		}()
		r = <-done
	}
	if r.err != nil {
		if asUID >= 0 {
			return 0, 0, 0, false
		}
		unavailable(t, r.err)
	}
	t.Cleanup(func() { syscall.Close(r.fd) })
	return r.fd, r.port, r.inode, true
}

// Two connected sockets share source 127.0.0.1:P and the destination port but
// go to different destination addresses (127.0.0.1 and 127.0.0.2), so the
// dump of port P lists both. The second one is owned by another uid when the
// test may switch uids (root); otherwise both have the test's uid.
func TestExactTCPLookupSharedSourcePort(t *testing.T) {
	l, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		unavailable(t, err)
	}
	t.Cleanup(func() { l.Close() })
	lport := l.Addr().(*net.TCPAddr).Port
	loop := net.IPv4(127, 0, 0, 1)
	dstA := &net.TCPAddr{IP: loop, Port: lport}
	dstB := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: lport}

	_, port, inodeA, _ := sharedPortSocket(t, -1, loop, 0, dstA)
	uidA := syscall.Getuid()
	uidB := uidA + 1 // another uid; valid when the test runs as root in a user namespace with a uid range
	_, _, inodeB, ok := sharedPortSocket(t, uidB, loop, port, dstB)
	if !ok {
		uidB = uidA
		_, _, inodeB, _ = sharedPortSocket(t, -1, loop, port, dstB)
		t.Logf("cannot switch uid: both sockets are owned by uid %d", uidA)
	}
	if inodeA == inodeB {
		t.Fatalf("both connections report inode %d", inodeA)
	}

	cases := []struct {
		name  string
		dst   net.IP
		inode int
		uid   int
	}{{"first destination", dstA.IP, inodeA, uidA}, {"second destination", dstB.IP, inodeB, uidB}}
	dumpUIDs := map[int]bool{uidA: true, uidB: true}

	for _, tc := range cases {
		t.Run("exact "+tc.name, func(t *testing.T) {
			calls := countExact(t)
			uid, inodes := GetSocketInfo("tcp", loop, uint(port), tc.dst, uint(lport))
			if *calls != 1 || !reflect.DeepEqual(inodes, []int{tc.inode}) || uid != tc.uid {
				t.Fatalf("calls %d, got uid %d inodes %v, want uid %d inode %d", *calls, uid, inodes, tc.uid, tc.inode)
			}
		})
		t.Run("dump fallback "+tc.name, func(t *testing.T) {
			t.Cleanup(func() { socketGetExact = SocketGetExact })
			socketGetExact = func(uint8, uint8, uint16, uint16, net.IP, net.IP) (*Socket, error) {
				return nil, errors.New("forced")
			}
			uid, inodes := GetSocketInfo("tcp", loop, uint(port), tc.dst, uint(lport))
			if !reflect.DeepEqual(inodes, []int{tc.inode}) {
				t.Fatalf("inodes %v, want [%d]", inodes, tc.inode)
			}
			// The dump keeps the uid of the last socket listed on the port,
			// which is not necessarily this connection's owner.
			if !dumpUIDs[uid] {
				t.Fatalf("uid %d is neither owner (%d, %d)", uid, uidA, uidB)
			}
			t.Logf("dump uid %d, owner uid %d", uid, tc.uid)
		})
	}
}
