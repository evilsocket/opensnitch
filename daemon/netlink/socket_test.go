package netlink

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

type Connection struct {
	SrcIP    net.IP
	DstIP    net.IP
	Protocol string
	SrcPort  uint
	DstPort  uint
	OutConn  net.Conn
	Listener net.Listener
}

func EstablishConnection(proto, dst string) (net.Conn, error) {
	c, err := net.Dial(proto, dst)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return c, nil
}

func ListenOnPort(proto, port string) (net.Listener, error) {
	// TODO: UDP -> ListenUDP() or ListenPacket()
	l, err := net.Listen(proto, port)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return l, nil
}

func setupConnection(proto string, connChan chan *Connection) {
	listnr, _ := ListenOnPort(proto, "127.0.0.1:55555")
	conn, err := EstablishConnection(proto, "127.0.0.1:55555")
	if err != nil {
		connChan <- nil
		return
	}
	laddr := strings.Split(conn.LocalAddr().String(), ":")
	daddr := strings.Split(conn.RemoteAddr().String(), ":")
	sport, _ := strconv.Atoi(laddr[1])
	dport, _ := strconv.Atoi(daddr[1])

	lconn := &Connection{
		SrcPort:  uint(sport),
		DstPort:  uint(dport),
		SrcIP:    net.ParseIP(laddr[0]),
		DstIP:    net.ParseIP(daddr[0]),
		Protocol: "tcp",
		Listener: listnr,
		OutConn:  conn,
	}
	connChan <- lconn
}

// TestNetlinkQueries tests queries to the kernel to get the inode of a connection.
// When using ProcFS as monitor method, we need that value to get the PID of an application.
// We also need it if for any reason auditd or ebpf doesn't return the PID of the application.
// TODO: test all the cases described in the GetSocketInfo() description.
func TestNetlinkTCPQueries(t *testing.T) {
	// netlink tests disabled by default, they cause random failures on restricted
	// environments.
	if os.Getenv("NETLINK_TESTS") == "" {
		t.Skip("Skipping netlink tests. Use NETLINK_TESTS=1 to launch these tests.")
	}

	connChan := make(chan *Connection)
	go setupConnection("tcp", connChan)
	conn := <-connChan
	if conn == nil {
		t.Error("TestParseTCPConnection, conn nil")
	}

	var inodes []int
	uid := -1
	t.Run("Test GetSocketInfo", func(t *testing.T) {
		uid, inodes = GetSocketInfo("tcp", conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort)

		if len(inodes) == 0 {
			t.Error("inodes empty")
		}
		if uid != os.Getuid() {
			t.Error("GetSocketInfo UID error:", uid, os.Getuid())
		}
	})

	t.Run("Test GetSocketInfoByInode", func(t *testing.T) {
		socket, err := GetSocketInfoByInode(fmt.Sprint(inodes[0]))
		if err != nil {
			t.Error("GetSocketInfoByInode error:", err)
		}
		if socket == nil {
			t.Error("GetSocketInfoByInode inode not found")
		}
		if socket.ID.SourcePort != uint16(conn.SrcPort) {
			t.Error("GetSocketInfoByInode dstPort error:", socket)
		}
		if socket.ID.DestinationPort != uint16(conn.DstPort) {
			t.Error("GetSocketInfoByInode dstPort error:", socket)
		}
		if socket.UID != uint32(os.Getuid()) {
			t.Error("GetSocketInfoByInode UID error:", socket, os.Getuid())
		}
	})

	conn.Listener.Close()
}
