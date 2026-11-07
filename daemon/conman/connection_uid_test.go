package conman

import (
	"net"
	"os"
	"os/exec"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/evilsocket/opensnitch/daemon/netfilter"
)

const noNFQueueUID = 0xffffffff

// outgoingSYN returns the first packet of src -> dst, as NFQUEUE hands it over.
func outgoingSYN(t *testing.T, src, dst *net.TCPAddr, uid uint32) *netfilter.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src.IP, DstIP: dst.IP}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(src.Port), DstPort: layers.TCPPort(dst.Port), SYN: true, Window: 1000}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp); err != nil {
		t.Fatal(err)
	}
	return &netfilter.Packet{
		Packet:          gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default),
		UID:             uid,
		NetworkProtocol: netfilter.IPv4,
	}
}

// A connected loopback socket held only by a child process, so the connection
// is not attributed to the test process itself. Returns the tuple and the pid.
func childHeldConnection(t *testing.T) (src, dst *net.TCPAddr, pid int) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { l.Close() })
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Skip(err)
	}
	s, err := l.Accept()
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { s.Close() })
	f, err := c.(*net.TCPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sleep", "30")
	cmd.ExtraFiles = []*os.File{f}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	src, dst = c.LocalAddr().(*net.TCPAddr), c.RemoteAddr().(*net.TCPAddr)
	f.Close()
	c.Close()
	return src, dst, cmd.Process.Pid
}

// Entry.UserId of a new connection: the NFQUEUE uid when the packet carries
// one, otherwise the owner uid reported by the socket lookup.
func TestConnectionUserID(t *testing.T) {
	src, dst, pid := childHeldConnection(t)
	for _, tc := range []struct {
		name string
		uid  uint32
		want int
	}{
		{"NFQUEUE uid absent", noNFQueueUID, os.Getuid()},
		{"NFQUEUE uid present", 4242, 4242},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewConnection(outgoingSYN(t, src, dst, tc.uid))
			if err != nil || c == nil {
				t.Fatalf("NewConnection: %v, %v", c, err)
			}
			if c.Process == nil || c.Process.ID != pid {
				t.Fatalf("attributed to %+v, want pid %d", c.Process, pid)
			}
			if c.Entry.UserId != tc.want {
				t.Fatalf("Entry.UserId = %d, want %d", c.Entry.UserId, tc.want)
			}
		})
	}
}
