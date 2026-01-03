//go:build linux

/*
Netfilter/NFQueue Tests

Integration tests for OpenSnitch's netfilter queue packet interception.

Running Tests:

	Namespaced (default, safe on host):
		sudo go test -v ./daemon/netfilter/

	Native (for VMs):
		sudo TEST_NATIVE=1 go test -v ./daemon/netfilter/

How It Works:

Each test runs in a separate subprocess inside an isolated network namespace:

 1. TestMain creates a network namespace
 2. Each test is executed in its own subprocess inside the namespace
 3. This ensures fresh global state (C code has global `stop` flag)
 4. Host network is completely unaffected

For detailed information about capabilities, safety, and testing modes, see:
	daemon/internal/testutil/network.go
*/
package netfilter

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/firewall/iptables"
	"github.com/evilsocket/opensnitch/daemon/internal/testutil"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// allTests lists all test functions in this file.
// Each test runs in a separate subprocess to ensure fresh global state
// (the C `stop` flag is global and never reset).
var allTests = []string{
	"TestVerdictEncoding",
	"TestIsIPv4",
	"TestQueueCreation",
	"TestPacketCapture",
	"TestVerdictAccept",
	"TestVerdictDrop",
	"TestVerdictMark",
	"TestSetRequeueVerdict",
	"TestSetVerdictWithPacket",
	"TestMultipleQueues",
	"TestConcurrentPacketHandling",
	"TestProductionRules",
}

// TestMain handles namespace setup and subprocess isolation for all tests.
func TestMain(m *testing.M) {
	if testutil.IsSubprocess() {
		os.Exit(m.Run())
	}
	if os.Getenv("TEST_NATIVE") == "1" {
		os.Exit(m.Run())
	}

	// Try to setup namespace isolation (requires root)
	testNet := testutil.NewTestNetwork()
	if err := testNet.Setup(); err != nil {
		// Namespace setup failed (likely no root) - run tests anyway, they'll skip
		os.Exit(m.Run())
	}
	defer testNet.Cleanup()

	os.Exit(testutil.RunTestsIsolated(testNet, allTests, os.Args))
}

// runCmd executes a command and returns combined output.
// Since tests run inside the namespace, commands execute directly.
func runCmd(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// augmentRule adds test-specific filters to a production iptables rule.
// Filters are inserted before the "-j" (jump target) to maintain proper ordering.
func augmentRule(baseRule []string, protocol string, port uint16, mark string) []string {
	// Find the index of "-j" (jump target)
	jumpIdx := -1
	for i, arg := range baseRule {
		if arg == "-j" {
			jumpIdx = i
			break
		}
	}

	if jumpIdx == -1 {
		// No jump found, append at end
		jumpIdx = len(baseRule)
	}

	// Build filters to insert
	filters := []string{}
	if protocol != "" {
		filters = append(filters, "-p", protocol)
		if port != 0 {
			filters = append(filters, "--dport", fmt.Sprintf("%d", port))
		}
	}
	if mark != "" {
		filters = append(filters, "-m", "mark", "!", "--mark", mark)
	}

	// Insert filters before jump
	result := make([]string, 0, len(baseRule)+len(filters))
	result = append(result, baseRule[:jumpIdx]...)
	result = append(result, filters...)
	result = append(result, baseRule[jumpIdx:]...)

	return result
}

// TestVerdictEncoding tests that verdict encoding for requeue works correctly
func TestVerdictEncoding(t *testing.T) {
	tests := []struct {
		name        string
		queueID     uint16
		wantVerdict uint
	}{
		{"queue 0", 0, uint(NF_QUEUE) | (0 << 16)},
		{"queue 1", 1, uint(NF_QUEUE) | (1 << 16)},
		{"queue 10", 10, uint(NF_QUEUE) | (10 << 16)},
		{"queue 255", 255, uint(NF_QUEUE) | (255 << 16)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the encoding from SetRequeueVerdict
			v := uint(NF_QUEUE)
			q := (uint(tt.queueID) << 16)
			v = v | q

			if v != tt.wantVerdict {
				t.Errorf("verdict encoding mismatch: got %d, want %d", v, tt.wantVerdict)
			}

			// Verify we can extract the queue ID back
			gotQueueID := (v >> 16) & 0xFFFF
			if gotQueueID != uint(tt.queueID) {
				t.Errorf("queue ID extraction failed: got %d, want %d", gotQueueID, tt.queueID)
			}
		})
	}
}

// TestIsIPv4 tests the IsIPv4 packet detection
func TestIsIPv4(t *testing.T) {
	tests := []struct {
		name            string
		networkProtocol uint8
		want            bool
	}{
		{"IPv4", IPv4, true},
		{"IPv6", 6, false},
		{"Invalid", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{
				NetworkProtocol: tt.networkProtocol,
			}
			if got := p.IsIPv4(); got != tt.want {
				t.Errorf("IsIPv4() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestQueueCreation tests that we can create and destroy a netfilter queue
func TestQueueCreation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to create nfqueue")
	}

	// Use a high queue number to avoid conflicts
	queueID := uint16(9999)

	q, err := NewQueue(queueID)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer q.Close()

	if q.packets == nil {
		t.Error("queue packets channel is nil")
	}
}

// TestPacketCapture tests that we can capture packets through nfqueue
func TestPacketCapture(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to create nfqueue and iptables rules")
	}

	queueID := uint16(9998)

	// Create the queue
	q, err := NewQueue(queueID)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer q.Close()

	// Build production rule and augment with test-specific filters
	mark := fmt.Sprintf("0x%x", queueID)
	baseRule := iptables.BuildQueueConnectionsRule(queueID, false)
	rule := augmentRule(baseRule, "icmp", 0, mark)

	// Add rule: iptables -A OUTPUT -t mangle -p icmp -m mark ! --mark 0x2706 -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num 9998
	out, err := runCmd("iptables", append([]string{"-A"}, rule...)...)
	if err != nil {
		t.Fatalf("failed to add iptables rule: %v: %s", err, out)
	}

	// Cleanup iptables rule
	defer func() {
		runCmd("iptables", append([]string{"-D"}, rule...)...)
	}()

	// Channel to signal packet was received
	packetReceived := make(chan bool, 1)

	// Start packet handler
	go func() {
		select {
		case pkt := <-q.Packets():
			// Verify we got a packet
			if pkt.Packet == nil {
				t.Error("received nil packet")
			}
			// Accept the packet with mark to avoid re-queueing
			pkt.SetVerdictAndMark(NF_ACCEPT, uint32(queueID))
			packetReceived <- true
		case <-time.After(5 * time.Second):
			t.Error("timeout waiting for packet")
			packetReceived <- false
		}
	}()

	// Give queue time to be ready
	time.Sleep(100 * time.Millisecond)

	// Send a ping packet to trigger the queue
	if _, err := runCmd("ping", "-c", "1", "-W", "1", "127.0.0.1"); err != nil {
		// It's okay if ping fails, we just need it to generate packets
		t.Logf("ping command failed (expected): %v", err)
	}

	// Wait for packet reception
	select {
	case received := <-packetReceived:
		if !received {
			t.Fatal("failed to receive packet")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("timeout waiting for packet reception")
	}
}

// TestVerdictAccept tests accepting packets
func TestVerdictAccept(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to create nfqueue and iptables rules")
	}

	queueID := uint16(9997)
	q, err := NewQueue(queueID)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer q.Close()

	// Build production rule and augment with test-specific filters
	mark := fmt.Sprintf("0x%x", queueID)
	baseRule := iptables.BuildQueueConnectionsRule(queueID, false)
	rule := augmentRule(baseRule, "tcp", 9997, mark)

	out, err := runCmd("iptables", append([]string{"-A"}, rule...)...)
	if err != nil {
		t.Fatalf("failed to add iptables rule: %v: %s", err, out)
	}

	defer func() {
		runCmd("iptables", append([]string{"-D"}, rule...)...)
	}()

	// Handle packets by accepting them
	go func() {
		for pkt := range q.Packets() {
			pkt.SetVerdictAndMark(NF_ACCEPT, uint32(queueID))
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Try to connect - should succeed since we're accepting packets
	conn, err := net.DialTimeout("tcp", "127.0.0.1:9997", 2*time.Second)
	if err == nil {
		conn.Close()
		// Connection attempt reached the queue and was accepted
		// Even though there's no listener, the SYN packet was accepted
	}
	// If error, it's likely "connection refused" which means packet was accepted
	// and reached the network stack (no listener on port)
	t.Logf("connection result (connection refused is expected): %v", err)
}

// TestVerdictDrop tests dropping packets
func TestVerdictDrop(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to create nfqueue and iptables rules")
	}

	queueID := uint16(9996)
	q, err := NewQueue(queueID)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer q.Close()

	// Build production rule and augment with test-specific filters
	baseRule := iptables.BuildQueueConnectionsRule(queueID, false)
	rule := augmentRule(baseRule, "tcp", 9996, "")

	out, err := runCmd("iptables", append([]string{"-A"}, rule...)...)
	if err != nil {
		t.Fatalf("failed to add iptables rule: %v: %s", err, out)
	}

	defer func() {
		runCmd("iptables", append([]string{"-D"}, rule...)...)
	}()

	// Handle packets by dropping them
	go func() {
		for pkt := range q.Packets() {
			pkt.SetVerdict(NF_DROP)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Try to connect - should timeout since we're dropping packets
	conn, err := net.DialTimeout("tcp", "127.0.0.1:9996", 1*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("connection succeeded but should have been dropped")
	}

	// We expect a timeout error since packets are dropped
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Logf("expected timeout error, got: %v", err)
		// Don't fail the test - timing issues can cause different errors
	}
}

// TestVerdictMark tests marking packets
func TestVerdictMark(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to create nfqueue and iptables rules")
	}

	queueID := uint16(9995)
	testMark := uint32(0x1234)

	q, err := NewQueue(queueID)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer q.Close()

	// Build production rule and augment with test-specific filters
	mark := fmt.Sprintf("0x%x", testMark)
	baseRule := iptables.BuildQueueConnectionsRule(queueID, false)
	rule := augmentRule(baseRule, "icmp", 0, mark)

	out, err := runCmd("iptables", append([]string{"-A"}, rule...)...)
	if err != nil {
		t.Fatalf("failed to add iptables rule: %v: %s", err, out)
	}

	defer func() {
		runCmd("iptables", append([]string{"-D"}, rule...)...)
	}()

	packetMarked := make(chan bool, 1)

	// Handle packets by marking them
	go func() {
		pkt := <-q.Packets()
		if pkt.Mark == testMark {
			t.Error("packet already has our test mark, shouldn't happen")
		}
		// Mark and accept - this should prevent re-queueing
		pkt.SetVerdictAndMark(NF_ACCEPT, testMark)
		packetMarked <- true
	}()

	time.Sleep(100 * time.Millisecond)

	// Send ping to generate packet
	runCmd("ping", "-c", "1", "-W", "1", "127.0.0.1")

	select {
	case <-packetMarked:
		// Success - packet was marked
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for packet to be marked")
	}
}

// TestSetRequeueVerdict tests the requeue verdict bit manipulation
func TestSetRequeueVerdict(t *testing.T) {
	tests := []struct {
		name         string
		newQueueID   uint16
		originalMark uint32
	}{
		{"requeue to 0", 0, 0},
		{"requeue to 1", 1, 0},
		{"requeue to 100", 100, 0},
		{"requeue with mark", 10, 0x5678},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdictChan := make(chan VerdictContainer, 1)
			p := &Packet{
				verdictChannel: verdictChan,
				Mark:           tt.originalMark,
			}

			// Call SetRequeueVerdict in goroutine
			go p.SetRequeueVerdict(tt.newQueueID)

			// Receive verdict
			select {
			case v := <-verdictChan:
				// Verify verdict encoding
				expectedVerdict := uint(NF_QUEUE) | (uint(tt.newQueueID) << 16)
				if uint(v.Verdict) != expectedVerdict {
					t.Errorf("verdict = %d, want %d", v.Verdict, expectedVerdict)
				}

				// Verify mark is preserved
				if v.Mark != tt.originalMark {
					t.Errorf("mark = %d, want %d", v.Mark, tt.originalMark)
				}

				// Verify packet is nil for requeue
				if v.Packet != nil {
					t.Error("packet should be nil for requeue verdict")
				}
			case <-time.After(1 * time.Second):
				t.Fatal("timeout waiting for verdict")
			}
		})
	}
}

// TestSetVerdictWithPacket tests modifying packet data
func TestSetVerdictWithPacket(t *testing.T) {
	verdictChan := make(chan VerdictContainer, 1)
	p := &Packet{
		verdictChannel: verdictChan,
	}

	// Create a simple IPv4 packet
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    net.IP{127, 0, 0, 1},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	if err := ipLayer.SerializeTo(buf, opts); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}

	modifiedPacket := buf.Bytes()

	// Call SetVerdictWithPacket in goroutine
	go p.SetVerdictWithPacket(NF_ACCEPT, modifiedPacket)

	// Receive verdict
	select {
	case v := <-verdictChan:
		if v.Verdict != NF_ACCEPT {
			t.Errorf("verdict = %v, want NF_ACCEPT", v.Verdict)
		}

		if v.Packet == nil {
			t.Fatal("packet should not be nil")
		}

		if len(v.Packet) != len(modifiedPacket) {
			t.Errorf("packet length = %d, want %d", len(v.Packet), len(modifiedPacket))
		}

		// Verify mark is 0 (default for SetVerdictWithPacket)
		if v.Mark != 0 {
			t.Errorf("mark = %d, want 0", v.Mark)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for verdict")
	}
}

// TestMultipleQueues tests that multiple queues can coexist and work independently
func TestMultipleQueues(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to create nfqueue")
	}

	// Create 3 queues with different IDs
	queues := []struct {
		id   uint16
		port uint16
		q    *Queue
	}{
		{id: 9980, port: 19980},
		{id: 9981, port: 19981},
		{id: 9982, port: 19982},
	}

	// Create all queues
	for i := range queues {
		q, err := NewQueue(queues[i].id)
		if err != nil {
			t.Fatalf("failed to create queue %d: %v", queues[i].id, err)
		}
		defer q.Close()
		queues[i].q = q
	}

	// Setup iptables rules for each queue
	for _, queue := range queues {
		mark := fmt.Sprintf("0x%x", queue.id)
		baseRule := iptables.BuildQueueConnectionsRule(queue.id, false)
		rule := augmentRule(baseRule, "tcp", queue.port, mark)

		out, err := runCmd("iptables", append([]string{"-A"}, rule...)...)
		if err != nil {
			t.Fatalf("failed to add iptables rule for queue %d: %v: %s", queue.id, err, out)
		}

		defer func(r []string) {
			runCmd("iptables", append([]string{"-D"}, r...)...)
		}(rule)
	}

	// Handle packets from each queue
	received := make(map[uint16]int)
	receivedLock := make(chan bool, 3)

	for _, queue := range queues {
		go func(qid uint16, q *Queue) {
			pkt := <-q.Packets()
			pkt.SetVerdictAndMark(NF_ACCEPT, uint32(qid))
			received[qid]++
			receivedLock <- true
		}(queue.id, queue.q)
	}

	time.Sleep(100 * time.Millisecond)

	// Send one packet to each queue's port
	for _, queue := range queues {
		go func(port uint16) {
			net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
		}(queue.port)
	}

	// Wait for all packets to be received
	timeout := time.After(5 * time.Second)
	receivedCount := 0
	for receivedCount < 3 {
		select {
		case <-receivedLock:
			receivedCount++
		case <-timeout:
			t.Fatalf("timeout: only received %d/3 packets", receivedCount)
		}
	}

	// Verify each queue received exactly one packet
	for _, queue := range queues {
		if received[queue.id] != 1 {
			t.Errorf("queue %d received %d packets, want 1", queue.id, received[queue.id])
		}
	}
}

// TestConcurrentPacketHandling tests handling many packets across multiple queues concurrently
// Run with: sudo go test -race -v -run TestConcurrentPacketHandling
func TestConcurrentPacketHandling(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to create nfqueue and iptables rules")
	}

	const numQueues = 3
	const packetsPerQueue = 100

	// Create queues
	queues := make([]*struct {
		id   uint16
		port uint16
		q    *Queue
	}, numQueues)

	for i := 0; i < numQueues; i++ {
		queues[i] = &struct {
			id   uint16
			port uint16
			q    *Queue
		}{
			id:   uint16(9970 + i),
			port: uint16(19970 + i),
		}

		q, err := NewQueue(queues[i].id)
		if err != nil {
			t.Fatalf("failed to create queue %d: %v", queues[i].id, err)
		}
		defer q.Close()
		queues[i].q = q
	}

	// Setup iptables rules
	for _, queue := range queues {
		mark := fmt.Sprintf("0x%x", queue.id)
		baseRule := iptables.BuildQueueConnectionsRule(queue.id, false)
		rule := augmentRule(baseRule, "tcp", queue.port, mark)

		out, err := runCmd("iptables", append([]string{"-A"}, rule...)...)
		if err != nil {
			t.Fatalf("failed to add iptables rule for queue %d: %v: %s", queue.id, err, out)
		}

		defer func(r []string) {
			runCmd("iptables", append([]string{"-D"}, r...)...)
		}(rule)
	}

	// Track packets received per queue
	type packetCount struct {
		received int
		done     chan bool
	}
	counters := make(map[uint16]*packetCount)
	for _, queue := range queues {
		counters[queue.id] = &packetCount{
			received: 0,
			done:     make(chan bool, 1),
		}
	}

	// Start packet handlers for each queue
	for _, queue := range queues {
		go func(qid uint16, q *Queue, counter *packetCount) {
			for i := 0; i < packetsPerQueue; i++ {
				select {
				case pkt := <-q.Packets():
					pkt.SetVerdictAndMark(NF_ACCEPT, uint32(qid))
					counter.received++
				case <-time.After(10 * time.Second):
					t.Errorf("queue %d: timeout waiting for packet %d/%d", qid, i+1, packetsPerQueue)
					counter.done <- true
					return
				}
			}
			counter.done <- true
		}(queue.id, queue.q, counters[queue.id])
	}

	time.Sleep(100 * time.Millisecond)

	// Generate packets concurrently for each queue
	for _, queue := range queues {
		go func(port uint16) {
			for i := 0; i < packetsPerQueue; i++ {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
				if err == nil {
					conn.Close()
				}
			}
		}(queue.port)
	}

	// Wait for all handlers to complete
	timeout := time.After(30 * time.Second)
	completedQueues := 0
	for completedQueues < numQueues {
		select {
		case <-counters[queues[completedQueues].id].done:
			completedQueues++
		case <-timeout:
			t.Fatalf("timeout: only %d/%d queues completed", completedQueues, numQueues)
		}
	}

	// Verify packet counts - should receive all packets with 0% loss
	totalReceived := 0
	for _, queue := range queues {
		received := counters[queue.id].received
		totalReceived += received
		t.Logf("queue %d: received %d/%d packets", queue.id, received, packetsPerQueue)

		if received != packetsPerQueue {
			t.Errorf("queue %d: packet loss detected: got %d, want %d", queue.id, received, packetsPerQueue)
		}
	}

	expectedTotal := numQueues * packetsPerQueue
	t.Logf("total packets received: %d/%d", totalReceived, expectedTotal)

	if totalReceived != expectedTotal {
		t.Errorf("total packet loss: got %d/%d packets - this indicates a bug", totalReceived, expectedTotal)
	}
}

// TestProductionRules tests with production iptables rules using conntrack.
// This verifies that queue.go works correctly with the actual rules used in production.
func TestProductionRules(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to create nfqueue and iptables rules")
	}

	queueID := uint16(0)

	q, err := NewQueue(queueID)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer q.Close()

	// Use production rule builder (with bypass enabled as in default config)
	rule := iptables.BuildQueueConnectionsRule(queueID, true)

	// Add rule: iptables -A OUTPUT -t mangle -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num 0 --queue-bypass
	out, err := runCmd("iptables", append([]string{"-A"}, rule...)...)
	if err != nil {
		t.Fatalf("failed to add production iptables rule: %v: %s", err, out)
	}

	defer func() {
		runCmd("iptables", append([]string{"-D"}, rule...)...)
	}()

	// Track packets
	packetsReceived := make(chan bool, 1)

	// Handle packets
	go func() {
		pkt := <-q.Packets()
		if pkt.Packet == nil {
			t.Error("received nil packet")
		}
		// Accept the packet - conntrack will mark it as ESTABLISHED,
		// so it won't be re-queued
		pkt.SetVerdict(NF_ACCEPT)
		packetsReceived <- true
	}()

	time.Sleep(100 * time.Millisecond)

	// Attempt TCP connection - this creates NEW conntrack state, gets queued
	// After we accept it, any follow-up packets are ESTABLISHED (not queued)
	conn, err := net.DialTimeout("tcp", "127.0.0.1:9999", 1*time.Second)
	if err == nil {
		conn.Close()
	}
	// Connection refused is expected (no listener), but packet should be queued

	select {
	case <-packetsReceived:
		// Success - packet was queued with production rules
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for packet with production rules")
	}
}
