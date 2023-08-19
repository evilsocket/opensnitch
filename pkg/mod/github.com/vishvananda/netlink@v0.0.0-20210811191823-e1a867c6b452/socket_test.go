// +build linux

package netlink

import (
	"log"
	"net"
	"os/user"
	"strconv"
	"syscall"
	"testing"
)

func TestSocketGet(t *testing.T) {
	defer setUpNetlinkTestWithLoopback(t)()

	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	conn, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	socket, err := SocketGet(localAddr, remoteAddr)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := socket.ID.Source, localAddr.IP; !got.Equal(want) {
		t.Fatalf("local ip = %v, want %v", got, want)
	}
	if got, want := socket.ID.Destination, remoteAddr.IP; !got.Equal(want) {
		t.Fatalf("remote ip = %v, want %v", got, want)
	}
	if got, want := int(socket.ID.SourcePort), localAddr.Port; got != want {
		t.Fatalf("local port = %d, want %d", got, want)
	}
	if got, want := int(socket.ID.DestinationPort), remoteAddr.Port; got != want {
		t.Fatalf("remote port = %d, want %d", got, want)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strconv.Itoa(int(socket.UID)), u.Uid; got != want {
		t.Fatalf("UID = %s, want %s", got, want)
	}
}

func TestSocketDiagTCPInfo(t *testing.T) {
	Family4 := uint8(syscall.AF_INET)
	Family6 := uint8(syscall.AF_INET6)
	families := []uint8{Family4, Family6}
	for _, wantFamily := range families {
		res, err := SocketDiagTCPInfo(wantFamily)
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range res {
			gotFamily := i.InetDiagMsg.Family
			if gotFamily != wantFamily {
				t.Fatalf("Socket family = %d, want %d", gotFamily, wantFamily)
			}
		}
	}
}
