//go:build linux
// +build linux

package netlink_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/net/bpf"
	"golang.org/x/net/nettest"
	"golang.org/x/sys/unix"
)

func TestIntegrationConn(t *testing.T) {
	t.Parallel()

	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial netlink: %v", err)
	}

	// Ask to send us an acknowledgement, which will contain an
	// error code (or success) and a copy of the payload we sent in
	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Acknowledge,
		},
	}

	// Perform a request, receive replies, and validate the replies
	msgs, err := c.Execute(req)
	if err != nil {
		t.Fatalf("failed to execute request: %v", err)
	}
	if want, got := 1, len(msgs); want != got {
		t.Fatalf("unexpected message count from netlink:\n- want: %v\n-  got: %v",
			want, got)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("error closing netlink connection: %v", err)
	}

	m := msgs[0]

	if want, got := 0, int(nlenc.Uint32(m.Data[0:4])); want != got {
		t.Fatalf("unexpected error code:\n- want: %v\n-  got: %v", want, got)
	}

	if want, got := 36, int(m.Header.Length); want != got {
		t.Fatalf("unexpected header length:\n- want: %v\n-  got: %v", want, got)
	}
	if want, got := netlink.Error, m.Header.Type; want != got {
		t.Fatalf("unexpected header type:\n- want: %v\n-  got: %v", want, got)
	}
	// Recent kernel versions (> 4.14) return a 256 here instead of a 0
	if want, wantAlt, got := 0, 256, int(m.Header.Flags); want != got && wantAlt != got {
		t.Fatalf("unexpected header flags:\n- want: %v or %v\n-  got: %v", want, wantAlt, got)
	}

	// Sequence number is not checked because we assign one at random when
	// a Conn is created. PID is not checked because running tests in parallel
	// results in only the first socket getting assigned the process's PID as
	// its netlink PID.

	// Skip error code and unmarshal the copy of request sent back by
	// skipping the success code at bytes 0-4
	var reply netlink.Message
	if err := (&reply).UnmarshalBinary(m.Data[4:]); err != nil {
		t.Fatalf("failed to unmarshal reply: %v", err)
	}

	if want, got := req.Header.Flags, reply.Header.Flags; want != got {
		t.Fatalf("unexpected copy header flags:\n- want: %v\n-  got: %v", want, got)
	}
	if want, got := len(req.Data), len(reply.Data); want != got {
		t.Fatalf("unexpected copy header data length:\n- want: %v\n-  got: %v", want, got)
	}
}

func TestIntegrationConnConcurrentManyConns(t *testing.T) {
	t.Parallel()
	skipShort(t)

	// Execute many concurrent operations on several netlink.Conns to ensure
	// the kernel is sending and receiving netlink messages to/from the correct
	// file descriptor.
	//
	// See: http://lists.infradead.org/pipermail/libnl/2017-February/002293.html.
	execN := func(n int) {
		c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
		if err != nil {
			panicf("failed to dial generic netlink: %v", err)
		}
		defer c.Close()

		req := netlink.Message{
			Header: netlink.Header{
				Flags: netlink.Request | netlink.Acknowledge,
			},
		}

		for i := 0; i < n; i++ {
			msgs, err := c.Execute(req)
			if err != nil {
				panicf("failed to send request: %v", err)
			}

			if l := len(msgs); l != 1 {
				panicf("unexpected number of reply messages: %d", l)
			}
		}
	}

	const (
		workers    = 16
		iterations = 10000
	)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			execN(iterations)
		}()
	}

	wg.Wait()
}

func TestIntegrationConnConcurrentOneConn(t *testing.T) {
	t.Parallel()
	skipShort(t)

	// Execute many concurrent operations on a single netlink.Conn.
	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial netlink: %v", err)
	}

	execN := func(n int) {
		req := netlink.Message{
			Header: netlink.Header{
				Flags: netlink.Request | netlink.Acknowledge,
			},
		}

		var res netlink.Message
		for i := 0; i < n; i++ {
			// Don't expect a "valid" request/reply because we are not serializing
			// our Send/Receive calls via Execute or with an external lock.
			//
			// Just verify that we don't trigger the race detector, we got a
			// valid netlink response, and it can be decoded as a valid
			// netlink message.
			if _, err := c.Send(req); err != nil {
				panicf("failed to send request: %v", err)
			}

			msgs, err := c.Receive()
			if err != nil {
				panicf("failed to receive reply: %v", err)
			}

			if l := len(msgs); l != 1 {
				panicf("unexpected number of reply messages: %d", l)
			}

			if err := res.UnmarshalBinary(msgs[0].Data[4:]); err != nil {
				panicf("failed to unmarshal reply: %v", err)
			}
		}
	}

	const (
		workers    = 16
		iterations = 10000
	)

	var wg sync.WaitGroup
	wg.Add(workers)
	defer wg.Wait()

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			execN(iterations)
		}()
	}
}

func TestIntegrationConnConcurrentClosePreventsReceive(t *testing.T) {
	t.Parallel()

	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial netlink: %v", err)
	}

	// Verify this test cannot block indefinitely due to Receive hanging after
	// a call to Close is completed.
	timer := time.AfterFunc(10*time.Second, func() {
		panic("test took too long")
	})
	defer timer.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()

	// The intent of this test is to schedule Close before Receive can ever
	// happen, resulting in EBADF. The test below covers the opposite case.
	sigC := make(chan struct{})
	go func() {
		defer wg.Done()

		<-sigC
		_, err := c.Receive()
		if err == nil {
			panicf("expected an error, but none occurred")
		}

		// Expect an error due to file descriptor being closed.
		serr := err.(*netlink.OpError).Err.(*os.SyscallError).Err
		if diff := cmp.Diff(unix.EBADF, serr); diff != "" {
			panicf("unexpected error from receive (-want +got):\n%s", diff)
		}
	}()

	if err := c.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}
	close(sigC)
}

func TestIntegrationConnConcurrentCloseUnblocksReceive(t *testing.T) {
	t.Parallel()

	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial netlink: %v", err)
	}

	// Verify this test cannot block indefinitely due to Receive hanging after
	// a call to Close is completed.
	timer := time.AfterFunc(10*time.Second, func() {
		panic("test took too long")
	})
	defer timer.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()

	// Try to enforce that Receive is scheduled before Close.
	sigC := make(chan struct{})
	go func() {
		defer wg.Done()

		// Multiple Close operations should be a no-op.
		<-sigC
		for i := 0; i < 5; i++ {
			time.Sleep(50 * time.Millisecond)

			if err := c.Close(); err != nil {
				panicf("failed to close: %v", err)
			}
		}
	}()

	close(sigC)
	_, err = c.Receive()
	if err == nil {
		t.Fatalf("expected an error, but none occurred")
	}

	// Expect an error due to the use of a closed file descriptor. Unfortunately
	// there doesn't seem to be a typed error for this.
	//
	// Previous versions of this code would wrap the internal/poll error which
	// *os.SyscallError which technically was incorrect. If necessary, revert
	// this behavior.
	serr := err.(*netlink.OpError).Err
	if diff := cmp.Diff("use of closed file", serr.Error()); diff != "" {
		t.Fatalf("unexpected error from receive (-want +got):\n%s", diff)
	}
}

func TestIntegrationConnConcurrentSerializeExecute(t *testing.T) {
	t.Parallel()
	skipShort(t)

	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial netlink: %v", err)
	}

	execN := func(n int) {
		req := netlink.Message{
			Header: netlink.Header{
				Flags: netlink.Request | netlink.Acknowledge,
			},
		}

		for i := 0; i < n; i++ {
			// Execute will internally call Validate to ensure its
			// request/response transaction is serialized appropriately, and
			// any errors doing so will be reported here.
			if _, err := c.Execute(req); err != nil {
				panicf("failed to execute: %v", err)
			}
		}
	}

	const (
		workers    = 4
		iterations = 2000
	)

	var wg sync.WaitGroup
	wg.Add(workers)
	defer wg.Wait()

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			execN(iterations)
		}()
	}
}

func TestIntegrationConnSetBuffersSyscallConn(t *testing.T) {
	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		// This test verifies both the force/non-force socket options depending
		// on the caller's privileges.
		{
			name:  "unprivileged",
			check: skipPrivileged,
		},
		{
			name:  "privileged",
			check: skipUnprivileged,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t)

			c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
			if err != nil {
				t.Fatalf("failed to dial netlink: %v", err)
			}
			defer c.Close()

			const (
				set = 8192

				// Per man 7 socket:
				//
				// "The kernel doubles this value (to allow space for
				// book‐keeping overhead) when it is set using setsockopt(2),
				// and this doubled value is returned by getsockopt(2).""
				want = set * 2
			)

			if err := c.SetReadBuffer(set); err != nil {
				t.Fatalf("failed to set read buffer size: %v", err)
			}

			if err := c.SetWriteBuffer(set); err != nil {
				t.Fatalf("failed to set write buffer size: %v", err)
			}

			// Now that we've set the buffers, we can check the size by asking the
			// kernel using SyscallConn and getsockopt.

			rc, err := c.SyscallConn()
			if err != nil {
				t.Fatalf("failed to get syscall conn: %v", err)
			}

			mustSize := func(opt int) int {
				var (
					value int
					serr  error
				)

				err := rc.Control(func(fd uintptr) {
					value, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
				})
				if err != nil {
					t.Fatalf("failed to call control: %v", err)
				}
				if serr != nil {
					t.Fatalf("failed to call getsockopt: %v", serr)
				}

				return value
			}

			if diff := cmp.Diff(want, mustSize(unix.SO_RCVBUF)); diff != "" {
				t.Fatalf("unexpected read buffer size (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(want, mustSize(unix.SO_SNDBUF)); diff != "" {
				t.Fatalf("unexpected write buffer size (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIntegrationConnSetBPFEmpty(t *testing.T) {
	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial netlink: %v", err)
	}
	defer c.Close()

	if err := c.SetBPF(nil); err == nil {
		t.Fatal("expected an error, but none occurred")
	}
}

func TestIntegrationConnSetBPF(t *testing.T) {
	t.Parallel()

	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial netlink: %v", err)
	}
	defer c.Close()

	// The sequence number which will be permitted by the BPF filter.
	// Using max uint32 helps us avoid dealing with host (netlink) vs
	// network (BPF) endianness during this test.
	const sequence uint32 = 0xffffffff

	prog, err := bpf.Assemble(testBPFProgram(sequence))
	if err != nil {
		t.Fatalf("failed to assemble BPF program: %v", err)
	}

	if err := c.SetBPF(prog); err != nil {
		t.Fatalf("failed to attach BPF program to socket: %v", err)
	}

	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Acknowledge,
		},
	}

	sequences := []struct {
		seq uint32
		ok  bool
	}{
		// OK, bad, OK.  Expect two messages to be received.
		{seq: sequence, ok: true},
		{seq: 10, ok: false},
		{seq: sequence, ok: true},
	}

	for _, s := range sequences {
		req.Header.Sequence = s.seq
		if _, err := c.Send(req); err != nil {
			t.Fatalf("failed to send with sequence %d: %v", s.seq, err)
		}

		if !s.ok {
			continue
		}

		msgs, err := c.Receive()
		if err != nil {
			t.Fatalf("failed to receive with sequence %d: %v", s.seq, err)
		}

		// Make sure the received message has the expected sequence number.
		if l := len(msgs); l != 1 {
			t.Fatalf("unexpected number of messages: %d", l)
		}

		if want, got := s.seq, msgs[0].Header.Sequence; want != got {
			t.Fatalf("unexpected reply sequence number:\n- want: %v\n-  got: %v",
				want, got)
		}
	}
	if err := c.RemoveBPF(); err != nil {
		t.Fatalf("failed to remove BPF filter: %v", err)
	}
}

func Test_testBPFProgram(t *testing.T) {
	// Verify the validity of our test BPF program.
	vm, err := bpf.NewVM(testBPFProgram(0xffffffff))
	if err != nil {
		t.Fatalf("failed to create BPF VM: %v", err)
	}

	msg := []byte{
		0x10, 0x00, 0x00, 0x00,
		0x01, 0x00,
		0x01, 0x00,
		// Allowed sequence number.
		0xff, 0xff, 0xff, 0xff,
		0x01, 0x00, 0x00, 0x00,
	}

	out, err := vm.Run(msg)
	if err != nil {
		t.Fatalf("failed to execute OK input: %v", err)
	}
	if out == 0 {
		t.Fatal("BPF filter dropped OK input")
	}

	msg = []byte{
		0x10, 0x00, 0x00, 0x00,
		0x01, 0x00,
		0x01, 0x00,
		// Bad sequence number.
		0x00, 0x11, 0x22, 0x33,
		0x01, 0x00, 0x00, 0x00,
	}

	out, err = vm.Run(msg)
	if err != nil {
		t.Fatalf("failed to execute bad input: %v", err)
	}
	if out != 0 {
		t.Fatal("BPF filter did not drop bad input")
	}
}

// testBPFProgram returns a BPF program which only allows frames with the
// input sequence number.
func testBPFProgram(allowSequence uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{
			Off:  8,
			Size: 4,
		},
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      allowSequence,
			SkipTrue: 1,
		},
		bpf.RetConstant{
			Val: 0,
		},
		bpf.RetConstant{
			Val: 128,
		},
	}
}

func TestIntegrationConnMulticast(t *testing.T) {
	skipUnprivileged(t)

	c, done := rtnlDial(t, 0)
	defer done()

	// Create an interface to trigger a notification, and remove it at the end
	// of the test.
	const ifName = "nltest0"
	defer shell(t, "ip", "link", "del", ifName)

	ifi := rtnlReceive(t, c, func() {
		shell(t, "ip", "tuntap", "add", ifName, "mode", "tun")
	})

	if diff := cmp.Diff(ifName, ifi); diff != "" {
		t.Fatalf("unexpected interface name (-want +got):\n%s", diff)
	}
}

func TestIntegrationConnNetNSUnprivileged(t *testing.T) {
	t.Parallel()

	skipPrivileged(t)

	// Created in CI build environment.
	const ns = "unpriv0"
	f, err := os.Open("/var/run/netns/" + ns)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("skipping, expected %s namespace to exist", ns)
		}

		t.Fatalf("failed to open namespace file: %v", err)
	}
	defer f.Close()

	_, err = netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{
		NetNS: int(f.Fd()),
	})
	if !os.IsPermission(err) {
		t.Fatalf("expected permission denied, but got: %v", err)
	}
}

func TestIntegrationConnSendTimeout(t *testing.T) {
	t.Parallel()

	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer c.Close()

	if err := c.SetWriteDeadline(time.Unix(0, 1)); err != nil {
		t.Fatalf("failed to set deadline: %v", err)
	}

	_, err = c.Send(netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Acknowledge,
		},
	})
	mustBeTimeoutNetError(t, err)
}

func TestIntegrationConnReceiveTimeout(t *testing.T) {
	t.Parallel()

	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer c.Close()

	if err := c.SetReadDeadline(time.Unix(0, 1)); err != nil {
		t.Fatalf("failed to set deadline: %v", err)
	}

	_, err = c.Receive()
	mustBeTimeoutNetError(t, err)
}

func TestIntegrationConnExecuteTimeout(t *testing.T) {
	t.Parallel()

	c, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer c.Close()

	if err := c.SetDeadline(time.Unix(0, 1)); err != nil {
		t.Fatalf("failed to set deadline: %v", err)
	}

	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Acknowledge,
		},
	}

	_, err = c.Execute(req)
	if err == nil {
		t.Fatal("expected an error, but none occurred")
	}

	mustBeTimeoutNetError(t, err)
}

func TestIntegrationRTNetlinkStrictCheckExtendedAcknowledge(t *testing.T) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		t.Fatalf("failed to open rtnetlink socket: %s", err)
	}
	defer c.Close()

	// Turn on extended acknowledgements and strict checking so rtnetlink
	// reports detailed error information regarding our invalid dump request.
	setStrictCheck(t, c)
	if err := c.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		t.Fatalf("failed to set extended acknowledge option: %v", err)
	}

	// The kernel will complain that this field isn't valid for a filtered dump
	// request.
	b, err := (&rtnetlink.RouteMessage{SrcLength: 1}).MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	_, err = c.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_GETROUTE,
			Flags: netlink.Request | netlink.Dump,
		},
		Data: b,
	})

	oerr, ok := err.(*netlink.OpError)
	if !ok {
		t.Fatalf("expected *netlink.OpError, but got: %T", err)
	}

	// Assume the message contents will be relatively static but don't hardcode
	// offset just in case things change.

	want := &netlink.OpError{
		Op:      "receive",
		Err:     unix.EINVAL,
		Message: "Invalid values in header for FIB dump request",
	}

	if diff := cmp.Diff(want, oerr); diff != "" {
		t.Fatalf("unexpected *netlink.OpError (-want +got):\n%s", diff)
	}
}

func TestIntegrationRTNetlinkRouteManipulation(t *testing.T) {
	skipUnprivileged(t)

	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		t.Fatalf("failed to open rtnetlink socket: %s", err)
	}
	defer c.Close()

	// Required for kernel route dump filtering.
	setStrictCheck(t, c)

	lo, err := nettest.LoopbackInterface()
	if err != nil {
		t.Fatalf("failed to get loopback: %v", err)
	}

	// Install synthetic routes in documentation ranges into a non-default table
	// which we will later dump.
	const (
		table   = 100
		ip4Mask = 32
		ip6Mask = 128
	)

	var (
		ip4 = &net.IPNet{
			IP:   net.IPv4(192, 2, 2, 1),
			Mask: net.CIDRMask(ip4Mask, ip4Mask),
		}

		ip6 = &net.IPNet{
			IP:   net.ParseIP("2001:db8::1"),
			Mask: net.CIDRMask(ip6Mask, ip6Mask),
		}

		want = []*net.IPNet{ip4, ip6}
	)

	rtmsgs := []rtnetlink.RouteMessage{
		{
			Family:    unix.AF_INET,
			DstLength: ip4Mask,
			Protocol:  unix.RTPROT_STATIC,
			Scope:     unix.RT_SCOPE_UNIVERSE,
			Type:      unix.RTN_UNICAST,
			Attributes: rtnetlink.RouteAttributes{
				Dst:      ip4.IP,
				OutIface: uint32(lo.Index),
				Table:    table,
			},
		},
		{
			Family:    unix.AF_INET6,
			DstLength: ip6Mask,
			Protocol:  unix.RTPROT_STATIC,
			Scope:     unix.RT_SCOPE_UNIVERSE,
			Type:      unix.RTN_UNICAST,
			Attributes: rtnetlink.RouteAttributes{
				Dst:      ip6.IP,
				OutIface: uint32(lo.Index),
				Table:    table,
			},
		},
	}

	// Verify we can send a batch of updates in one syscall.
	var msgs []netlink.Message
	for _, m := range rtmsgs {
		b, err := m.MarshalBinary()
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		msgs = append(msgs, netlink.Message{
			Header: netlink.Header{
				Type:  unix.RTM_NEWROUTE,
				Flags: netlink.Request | netlink.Create | netlink.Replace,
			},
			Data: b,
		})
	}

	if _, err := c.SendMessages(msgs); err != nil {
		t.Fatalf("failed to add routes: %v", err)
	}

	// Only dump routes from the specified table.
	b, err := (&rtnetlink.RouteMessage{
		Attributes: rtnetlink.RouteAttributes{Table: table},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	routes, err := c.Execute(
		netlink.Message{
			Header: netlink.Header{
				Type:  unix.RTM_GETROUTE,
				Flags: netlink.Request | netlink.Dump,
			},
			Data: b,
		},
	)
	if err != nil {
		t.Fatalf("failed to dump routes: %v", err)
	}

	// Parse the routes back to Go structures.
	got := make([]*net.IPNet, 0, len(routes))
	for _, r := range routes {
		var rtm rtnetlink.RouteMessage
		if err := rtm.UnmarshalBinary(r.Data); err != nil {
			t.Fatalf("failed to unmarshal route: %v", err)
		}

		got = append(got, &net.IPNet{
			IP:   rtm.Attributes.Dst,
			Mask: net.CIDRMask(int(rtm.DstLength), int(rtm.DstLength)),
		})
	}

	// Now clear the routes and verify they're removed before ensuring we got
	// the expected routes.
	for i := range msgs {
		msgs[i].Header.Type = unix.RTM_DELROUTE
		msgs[i].Header.Flags = netlink.Request | netlink.Acknowledge
	}

	if _, err := c.SendMessages(msgs); err != nil {
		t.Fatalf("failed to send: %v", err)
	}
	if _, err := c.Receive(); err != nil {
		t.Fatalf("failed to receive: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected routes (-want +got):\n%s", diff)
	}
}

func TestIntegrationConnNetNSExplicit(t *testing.T) {
	skipUnprivileged(t)

	// Create a network namespace for use within this test.
	const ns = "nltest0"
	shell(t, "ip", "netns", "add", ns)
	defer shell(t, "ip", "netns", "del", ns)

	f, err := os.Open("/var/run/netns/" + ns)
	if err != nil {
		t.Fatalf("failed to open namespace file: %v", err)
	}
	defer f.Close()

	// Create a connection in each the host namespace and the new network
	// namespace. We will use these to validate that a namespace was entered
	// and that an interface creation notification was only visible to the
	// connection within the namespace.
	hostC, hostDone := rtnlDial(t, 0)
	defer hostDone()

	nsC, nsDone := rtnlDial(t, int(f.Fd()))
	defer nsDone()

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()

	go func() {
		defer wg.Done()

		_, err := hostC.Receive()
		if err == nil {
			panic("received netlink message in host namespace")
		}

		// Timeout means we were interrupted, so return.
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			return
		}

		panicf("failed to receive in host namespace: %v", err)
	}()

	// Create a temporary interface within the new network namespace.
	const ifName = "nltestns0"
	defer shell(t, "ip", "netns", "exec", ns, "ip", "link", "del", ifName)

	ifi := rtnlReceive(t, nsC, func() {
		// Trigger a notification in the new namespace.
		shell(t, "ip", "netns", "exec", ns, "ip", "tuntap", "add", ifName, "mode", "tun")
	})

	// And finally interrupt the host connection so it can exit its
	// receive goroutine.
	if err := hostC.SetDeadline(time.Unix(1, 0)); err != nil {
		t.Fatalf("failed to interrupt host connection: %v", err)
	}

	if diff := cmp.Diff(ifName, ifi); diff != "" {
		t.Fatalf("unexpected interface name (-want +got):\n%s", diff)
	}
}

func TestIntegrationConnNetNSImplicit(t *testing.T) {
	skipUnprivileged(t)

	// Create a network namespace for use within this test.
	const ns = "nltest0"
	shell(t, "ip", "netns", "add", ns)
	defer shell(t, "ip", "netns", "del", ns)

	f, err := os.Open("/var/run/netns/" + ns)
	if err != nil {
		t.Fatalf("failed to open namespace file: %v", err)
	}
	defer f.Close()

	// Create an interface in the new namespace. We will attempt to find it later.
	const ifName = "nltestns0"
	shell(t, "ip", "netns", "exec", ns, "ip", "tuntap", "add", ifName, "mode", "tun")
	defer shell(t, "ip", "netns", "exec", ns, "ip", "link", "del", ifName)

	// We're going to manipulate the network namespace of this thread, so we
	// must lock OS thread and keep track of the original namespace for later.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	threadNS, err := netlink.ThreadNetNS()
	if err != nil {
		t.Fatalf("failed to get current network namespace: %v", err)
	}
	defer threadNS.Close()

	if err := threadNS.Set(int(f.Fd())); err != nil {
		t.Fatalf("failed to enter new network namespace: %v", err)
	}

	// A newly created netlink connection should enter the new network namespace
	// associated with this thread automatically.
	if !findLink(t, ifName) {
		t.Fatalf("did not find interface %q in namespace %q", ifName, ns)
	}

	// Return to the default namespace.
	//
	// A newly created netlink connection should NOT find the link because it
	// is now in the default namespace.
	if err := threadNS.Restore(); err != nil {
		t.Fatalf("failed to restore original network namespace: %v", err)
	}

	if findLink(t, ifName) {
		t.Fatalf("found interface %q in default namespace", ifName)
	}
}

func findLink(t *testing.T, name string) bool {
	t.Helper()

	_, err := net.InterfaceByName(name)
	return err == nil
}

func mustBeTimeoutNetError(t *testing.T, err error) {
	t.Helper()

	nerr, ok := err.(net.Error)
	if !ok {
		t.Fatalf("expected net.Error, but got: %T", err)
	}
	if !nerr.Timeout() {
		t.Fatalf("error did not indicate a timeout")
	}
}

func rtnlDial(t *testing.T, netNS int) (*netlink.Conn, func()) {
	t.Helper()

	timer := time.AfterFunc(10*time.Second, func() {
		panic("test took too long")
	})

	c, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{
		Groups: unix.RTMGRP_LINK,
		NetNS:  netNS,
	})
	if err != nil {
		t.Fatalf("failed to dial rtnetlink: %v", err)
	}

	return c, func() {
		if err := c.Close(); err != nil {
			t.Fatalf("failed to close rtnetlink connection: %v", err)
		}

		// Stop the timer to prevent a panic if other tests run for a long time.
		timer.Stop()
	}
}

func rtnlReceive(t *testing.T, c *netlink.Conn, do func()) string {
	t.Helper()

	// Receive messages in goroutine.
	msgC := make(chan rtnetlink.LinkMessage)
	go func() {
		msgs, err := c.Receive()
		if err != nil {
			panicf("failed to receive rtnetlink messages: %v", err)
		}

		var rtmsg rtnetlink.LinkMessage
		if err := rtmsg.UnmarshalBinary(msgs[0].Data); err != nil {
			panicf("failed to unmarshal rtnetlink message: %v", err)
		}

		msgC <- rtmsg
	}()

	// Execute the function which will generate messages, and then wait for
	// a message.
	do()
	m := <-msgC

	return m.Attributes.Name
}

func setStrictCheck(t *testing.T, c *netlink.Conn) {
	if err := c.SetOption(netlink.GetStrictCheck, true); err != nil {
		// TODO(mdlayher): use errors.Is when we drop support for Go 1.12.
		if err.(*netlink.OpError).Err == unix.ENOPROTOOPT {
			t.Skipf("skipping, netlink strict checking is not supported on this kernel")
		}

		t.Fatalf("failed to set strict check option: %v", err)
	}
}

func skipPrivileged(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if u.Uid == "0" {
		t.Skip("skipping, test must be run as non-root user")
	}
}

func skipUnprivileged(t *testing.T) {
	const ifName = "nlprobe0"
	shell(t, "ip", "tuntap", "add", ifName, "mode", "tun")
	shell(t, "ip", "link", "del", ifName)
}

func skipShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping in short test mode")
	}
}

func shell(t *testing.T, name string, arg ...string) {
	t.Helper()

	t.Logf("$ %s %v", name, arg)

	cmd := exec.Command(name, arg...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start command %q: %v", name, err)
	}

	if err := cmd.Wait(); err != nil {
		// Shell operations in these tests require elevated privileges.
		if cmd.ProcessState.ExitCode() == int(unix.EPERM) {
			t.Skipf("skipping, permission denied: %v", err)
		}

		t.Fatalf("failed to wait for command %q: %v", name, err)
	}
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
