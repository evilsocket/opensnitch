package ui

// The real path of the list of blocks: TASK_START -> handleNotification ->
// monitorPortScanBlocks -> TaskMgr -> monitorTaskEvents -> stream.Send, with
// only the stream and the port scan responder replaced. Nothing else drives it:
// the task's own tests build a Monitor directly.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/tasks"
	"github.com/evilsocket/opensnitch/daemon/tasks/portscanblocks"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"google.golang.org/grpc"
)

type psbStream struct {
	grpc.ClientStream
	mu       sync.Mutex
	replies  []*protocol.NotificationReply
	inflight int32
	overlaps int32
	maxIn    int32
	delay    time.Duration
}

func (s *psbStream) Send(r *protocol.NotificationReply) error {
	n := atomic.AddInt32(&s.inflight, 1)
	if n > 1 {
		atomic.AddInt32(&s.overlaps, 1)
	}
	for {
		m := atomic.LoadInt32(&s.maxIn)
		if n <= m || atomic.CompareAndSwapInt32(&s.maxIn, m, n) {
			break
		}
	}
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	s.replies = append(s.replies, r)
	s.mu.Unlock()
	atomic.AddInt32(&s.inflight, -1)
	return nil
}
func (s *psbStream) Recv() (*protocol.Notification, error) { select {} }

func (s *psbStream) byID(id uint64) (ok, errs []*protocol.NotificationReply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.replies {
		if r.Id != id {
			continue
		}
		if r.Code == protocol.NotificationReplyCode_ERROR {
			errs = append(errs, r)
		} else {
			ok = append(ok, r)
		}
	}
	return
}

type psbResponder struct {
	mu         sync.Mutex
	list       []portscanblocks.Blocked
	released   []netip.Addr
	forgotten  []netip.Addr
	detections []portscanblocks.Detected
	// confirmed records each ConfirmBlock, with its force flag.
	confirmed []psbConfirm
}

type psbConfirm struct {
	addr  netip.Addr
	force bool
}

func (r *psbResponder) ConfirmBlock(a netip.Addr, force bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.confirmed = append(r.confirmed, psbConfirm{a, force})
	return nil
}
func (r *psbResponder) DetectionList(limit int) ([]portscanblocks.Detected, int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.detections
	if limit >= 0 && len(list) > limit {
		list = list[:limit]
	}
	return append([]portscanblocks.Detected(nil), list...), len(r.detections), true
}
func (r *psbResponder) ReleaseBlock(a netip.Addr) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.list {
		if b.Addr == a.String() {
			r.released = append(r.released, a)
			return true, nil
		}
	}
	return false, nil
}
func (r *psbResponder) Forget(a netip.Addr) (bool, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.list {
		if b.Addr == a.String() {
			r.forgotten = append(r.forgotten, a)
			return true, true, nil
		}
	}
	for _, d := range r.detections {
		if d.Addr == a.String() {
			r.forgotten = append(r.forgotten, a)
			return true, false, nil
		}
	}
	return false, false, nil
}
func (r *psbResponder) DismissProposal(netip.Addr) {}
func (r *psbResponder) BlockInfo(a netip.Addr) (portscanblocks.Info, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.list {
		if b.Addr == a.String() {
			return portscanblocks.Info{Blocked: b, Firewall: "table inet opensnitch-portscan {}",
				Scan: &portscanblocks.Scan{Method: "syn", SrcMAC: "02:00:00:00:00:01",
					SamplePorts: []uint32{22, 80}}}, true
		}
	}
	return portscanblocks.Info{}, false
}
func (r *psbResponder) BlockedList(limit int) ([]portscanblocks.Blocked, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.list
	if limit >= 0 && len(list) > limit {
		list = list[:limit]
	}
	return append([]portscanblocks.Blocked(nil), list...), len(r.list)
}

// The real TaskManager goroutine reads streamNotifications from the client it
// was started with, so every test shares one client/stream pair.
var (
	psbOnce   sync.Once
	psbC      *Client
	psbS      *psbStream
	psbNextID uint64 = 1_700_000_000_000
)

func psbShared() (*Client, *psbStream) {
	psbOnce.Do(func() {
		psbS = &psbStream{}
		psbC = &Client{streamNotifications: psbS}
		TaskMgr = tasks.NewTaskManager()
		go psbC.monitorTaskManager(TaskMgr)
	})
	return psbC, psbS
}

func psbID() uint64 { return atomic.AddUint64(&psbNextID, 1) }

func psbStart(c *Client, s *psbStream, id uint64, interval string) {
	data := fmt.Sprintf(`{"name":"portscan-blocks","data":{"interval":%q}}`, interval)
	c.handleNotification(s, &protocol.Notification{Id: id, Type: protocol.Action_TASK_START, Data: data})
}
func psbStop(c *Client, s *psbStream, id uint64) {
	c.handleNotification(s, &protocol.Notification{Id: id, Type: protocol.Action_TASK_STOP,
		Data: `{"name":"portscan-blocks","data":{"interval":"2s"}}`})
}

func psbEntries(n int) []portscanblocks.Blocked {
	out := make([]portscanblocks.Blocked, n)
	for i := range out {
		out[i] = portscanblocks.Blocked{Addr: fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255),
			Reason: "TCP SYN scan", ExpiresAt: time.Now().Add(time.Hour).Unix(), Remaining: 3600}
	}
	return out
}

func TestPortScanBlocksWiring(t *testing.T) {
	c, s := psbShared()
	r := &psbResponder{list: psbEntries(3)}
	c.SetPortScanResponder(r)

	id := psbID()
	psbStart(c, s, id, "500ms")
	// Waited for, not slept on: under load the ticker's first pushes can
	// come later than a fixed 1.3 s, and the test would fail with nothing
	// wrong.
	start := time.Now()
	psbWaitFor(func() bool { ok, _ := s.byID(id); return len(ok) >= 2 })
	ok, errs := s.byID(id)
	t.Logf("after %v at 500ms: %d snapshots, %d errors", time.Since(start).Round(time.Millisecond), len(ok), len(errs))
	if len(ok) < 2 {
		t.Fatalf("real path delivered %d snapshots in 10s", len(ok))
	}
	var snap portscanblocks.Snapshot
	if err := json.Unmarshal([]byte(ok[0].Data), &snap); err != nil || snap.Total != 3 {
		t.Fatalf("snapshot %q err=%v", ok[0].Data, err)
	}

	// detection torn down while the list is on screen
	c.SetPortScanResponder(nil)
	psbWaitFor(func() bool { _, errs := s.byID(id); return len(errs) > 0 })
	_, errs = s.byID(id)
	t.Logf("responder removed: %d error replies, last=%q", len(errs), func() string {
		if len(errs) == 0 {
			return ""
		}
		return errs[len(errs)-1].Data
	}())
	if len(errs) == 0 {
		t.Errorf("the task did not report that detection went away")
	}
	c.SetPortScanResponder(r)

	// second TASK_START while the first is running
	id2 := psbID()
	psbStart(c, s, id2, "500ms")
	time.Sleep(700 * time.Millisecond)
	ok2, errs2 := s.byID(id2)
	t.Logf("second TASK_START: %d snapshots, %d errors (%v)", len(ok2), len(errs2), func() []string {
		var o []string
		for _, e := range errs2 {
			o = append(o, e.Data)
		}
		return o
	}())

	psbStop(c, s, psbID())
	time.Sleep(700 * time.Millisecond)
	before, _ := s.byID(id)
	time.Sleep(1200 * time.Millisecond)
	after, _ := s.byID(id)
	t.Logf("after TASK_STOP: %d -> %d snapshots", len(before), len(after))
	if len(after) != len(before) {
		t.Errorf("task kept pushing after TASK_STOP")
	}
}

func TestPortScanBlocksStartStopChurn(t *testing.T) {
	c, s := psbShared()
	c.SetPortScanResponder(&psbResponder{list: psbEntries(10)})
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	g0 := runtime.NumGoroutine()
	const N = 2000
	t0 := time.Now()
	for i := 0; i < N; i++ {
		psbStart(c, s, psbID(), "500ms")
		psbStop(c, s, psbID())
	}
	el := time.Since(t0)
	time.Sleep(1500 * time.Millisecond)
	runtime.GC()
	g1 := runtime.NumGoroutine()
	t.Logf("%d START/STOP cycles in %v; goroutines %d -> %d", N, el, g0, g1)
	if g1-g0 > 5 {
		t.Errorf("goroutine leak: %d", g1-g0)
	}
	// START, then the stream drops (StopTempTasks), then START again.
	id := psbID()
	psbStart(c, s, id, "500ms")
	time.Sleep(300 * time.Millisecond)
	TaskMgr.StopTempTasks()
	id2 := psbID()
	psbStart(c, s, id2, "500ms")
	psbWaitFor(func() bool { ok, _ := s.byID(id2); return len(ok) > 0 })
	ok, errs := s.byID(id2)
	t.Logf("START after a disconnect: %d snapshots, %d errors", len(ok), len(errs))
	if len(ok) == 0 {
		t.Errorf("a TASK_START after a disconnect delivered nothing")
	}
	psbStop(c, s, psbID())
	time.Sleep(300 * time.Millisecond)
}

// Two goroutines call Send on the same stream: the task's monitorTaskEvents and
// the notification loop answering PORTSCAN_UNBLOCK. grpc-go: "it is not safe
// to call SendMsg on the same stream in different goroutines".
func TestPortScanBlocksConcurrentSend(t *testing.T) {
	c, s := psbShared()
	c.SetPortScanResponder(&psbResponder{list: psbEntries(512)})
	s.delay = 3 * time.Millisecond
	defer func() { s.delay = 0 }()
	atomic.StoreInt32(&s.overlaps, 0)
	id := psbID()
	psbStart(c, s, id, "500ms")
	deadline := time.Now().Add(3 * time.Second)
	n := 0
	for time.Now().Before(deadline) {
		c.handleNotification(s, &protocol.Notification{Id: psbID(),
			Type: protocol.Action_PORTSCAN_UNBLOCK, Data: `{"ip":"10.0.0.1"}`})
		n++
	}
	psbStop(c, s, psbID())
	time.Sleep(300 * time.Millisecond)
	ok, _ := s.byID(id)
	t.Logf("%d UNBLOCK replies + %d snapshots in 3s; overlapping Send calls: %d (max in flight %d)",
		n, len(ok), atomic.LoadInt32(&s.overlaps), atomic.LoadInt32(&s.maxIn))
	if o := atomic.LoadInt32(&s.overlaps); o != 0 {
		t.Fatalf("%d Send calls overlapped on one stream, which grpc-go does not allow", o)
	}
}

// TestPortScanUnblockOfAnUnblockedAddressSaysSo: answering OK, with the log
// saying "released the block on X" at the most visible level, for any address
// would let anyone who can reach the socket write the one record of early
// releases.
func TestPortScanUnblockOfAnUnblockedAddressSaysSo(t *testing.T) {
	c, s := psbShared()
	r := &psbResponder{list: psbEntries(1)}
	c.SetPortScanResponder(r)
	for _, tc := range []struct {
		addr string
		ok   bool
	}{{"10.0.0.0", true}, {"192.0.2.99", false}} {
		id := psbID()
		c.handleNotification(s, &protocol.Notification{Id: id,
			Type: protocol.Action_PORTSCAN_UNBLOCK, Data: `{"ip":"` + tc.addr + `"}`})
		ok, errs := s.byID(id)
		if tc.ok && (len(ok) != 1 || len(errs) != 0) {
			t.Errorf("%s was blocked: got %d OK and %d error replies", tc.addr, len(ok), len(errs))
		}
		if !tc.ok && (len(errs) != 1 || !strings.Contains(errs[0].Data, "not blocked")) {
			t.Errorf("%s was not blocked: got %d OK and %v", tc.addr, len(ok), errs)
		}
	}
}

// TestPortScanBlocksSnapshotJSONSize: at 65536 blocks the GUI still gets
// 512 rows and a total, not a 65536-row payload.
func TestPortScanBlocksSnapshotJSONSize(t *testing.T) {
	c, s := psbShared()
	c.SetPortScanResponder(&psbResponder{list: psbEntries(65536)})
	id := psbID()
	psbStart(c, s, id, "500ms")
	time.Sleep(700 * time.Millisecond)
	psbStop(c, s, psbID())
	time.Sleep(300 * time.Millisecond)
	ok, _ := s.byID(id)
	if len(ok) == 0 {
		t.Fatal("no snapshot")
	}
	var snap portscanblocks.Snapshot
	_ = json.Unmarshal([]byte(ok[0].Data), &snap)
	t.Logf("65536 blocks: snapshot %d bytes, %d rows, total %d, omitted %d",
		len(ok[0].Data), len(snap.Blocks), snap.Total, snap.Omitted)
	if !strings.Contains(ok[0].Data, `"omitted":65024`) {
		t.Errorf("omitted count wrong")
	}
}

// psbWaitFor polls cond for up to ten seconds. The tests above wait for what
// they expect to see rather than sleeping a fixed time, which a loaded
// machine can overrun with nothing wrong; waiting for something NOT to
// happen still takes a fixed delay.
func psbWaitFor(cond func() bool) {
	for deadline := time.Now().Add(10 * time.Second); !cond() && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}
}

// TestPortScanBlockInfoReplies: the details of a block travel as JSON in the
// reply's data; an address that is not blocked, or not an address, is an error.
func TestPortScanBlockInfoReplies(t *testing.T) {
	c, s := psbShared()
	c.SetPortScanResponder(&psbResponder{list: psbEntries(1)})

	id := psbID()
	c.handleNotification(s, &protocol.Notification{Id: id,
		Type: protocol.Action_PORTSCAN_BLOCK_INFO, Data: `{"ip":"10.0.0.0"}`})
	ok, errs := s.byID(id)
	if len(ok) != 1 || len(errs) != 0 {
		t.Fatalf("a blocked address: got %d OK and %v", len(ok), errs)
	}
	var info portscanblocks.Info
	if err := json.Unmarshal([]byte(ok[0].Data), &info); err != nil {
		t.Fatalf("the reply is not an Info: %v: %q", err, ok[0].Data)
	}
	if info.Addr != "10.0.0.0" || info.Scan == nil || info.Scan.SrcMAC != "02:00:00:00:00:01" ||
		len(info.Scan.SamplePorts) != 2 || info.Firewall == "" {
		t.Fatalf("the reply lost fields: %+v", info)
	}

	for _, data := range []string{`{"ip":"192.0.2.99"}`, `{"ip":"not an address"}`, `nonsense`} {
		id := psbID()
		c.handleNotification(s, &protocol.Notification{Id: id,
			Type: protocol.Action_PORTSCAN_BLOCK_INFO, Data: data})
		ok, errs := s.byID(id)
		if len(ok) != 0 || len(errs) != 1 {
			t.Errorf("%s: got %d OK and %d error replies, want one error", data, len(ok), len(errs))
		}
	}

	c.SetPortScanResponder(nil)
	id = psbID()
	c.handleNotification(s, &protocol.Notification{Id: id,
		Type: protocol.Action_PORTSCAN_BLOCK_INFO, Data: `{"ip":"10.0.0.0"}`})
	if _, errs := s.byID(id); len(errs) != 1 || !strings.Contains(errs[0].Data, "not running") {
		t.Fatalf("detection stopped: got %v, want an error saying so", errs)
	}
}

// TestPortScanBlockCarriesForce: a block asked from the history says whether
// the user chose to block on a detection not enough on its own; the field is
// absent from the answer to a notification, which is never forced.
func TestPortScanBlockCarriesForce(t *testing.T) {
	c, s := psbShared()
	r := &psbResponder{}
	c.SetPortScanResponder(r)
	defer c.SetPortScanResponder(nil)
	for _, data := range []string{`{"ip":"192.0.2.7","dismiss":false}`, `{"ip":"192.0.2.8","force":true}`} {
		id := psbID()
		c.handleNotification(s, &protocol.Notification{Id: id, Type: protocol.Action_PORTSCAN_BLOCK, Data: data})
		if ok, errs := s.byID(id); len(ok) != 1 || len(errs) != 0 {
			t.Fatalf("%s: got %d OK and %v", data, len(ok), errs)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	want := []psbConfirm{{netip.MustParseAddr("192.0.2.7"), false}, {netip.MustParseAddr("192.0.2.8"), true}}
	if len(r.confirmed) != 2 || r.confirmed[0] != want[0] || r.confirmed[1] != want[1] {
		t.Fatalf("ConfirmBlock calls = %+v, want %+v", r.confirmed, want)
	}
}

// TestPortScanBlocksSnapshotCarriesDetections: the list the GUI receives holds
// the sources the daemon reported and does not block, and whether it can block.
func TestPortScanBlocksSnapshotCarriesDetections(t *testing.T) {
	c := &Client{}
	c.SetPortScanResponder(&psbResponder{detections: []portscanblocks.Detected{
		{Addr: "192.0.2.9", Method: "tcp-syn", Status: "unanswered", Eligible: true}}})
	list, total, canBlock, err := portScanLister{c: c}.DetectionList(portscanblocks.MaxDetections)
	if err != nil || total != 1 || !canBlock || len(list) != 1 || list[0].Status != "unanswered" {
		t.Fatalf("DetectionList = %+v, %d, %v, %v", list, total, canBlock, err)
	}
	c.SetPortScanResponder(nil)
	if _, _, _, err := (portScanLister{c: c}).DetectionList(1); err == nil {
		t.Fatal("detection stopped: want an error, not an empty history")
	}
}

// TestPortScanUnblockWithForgetDeletes: "forget" on PORTSCAN_UNBLOCK removes
// the source from the list (a detection too, which a release cannot reach),
// and is refused for an address the list does not hold; without it, the
// request is the release it always was.
func TestPortScanUnblockWithForgetDeletes(t *testing.T) {
	c, s := psbShared()
	r := &psbResponder{list: psbEntries(1),
		detections: []portscanblocks.Detected{{Addr: "192.0.2.70", Status: "unanswered"}}}
	c.SetPortScanResponder(r)
	for _, tc := range []struct {
		data string
		ok   bool
	}{
		{`{"ip":"192.0.2.70","forget":true}`, true},
		{`{"ip":"10.0.0.0","forget":true}`, true},
		{`{"ip":"192.0.2.99","forget":true}`, false},
		{`{"ip":"192.0.2.70"}`, false},
	} {
		id := psbID()
		c.handleNotification(s, &protocol.Notification{Id: id,
			Type: protocol.Action_PORTSCAN_UNBLOCK, Data: tc.data})
		ok, errs := s.byID(id)
		if tc.ok != (len(ok) == 1 && len(errs) == 0) {
			t.Errorf("%s: got %d OK and %v", tc.data, len(ok), errs)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.forgotten) != 2 || len(r.released) != 0 {
		t.Errorf("forgotten %v, released %v; want the two listed sources forgotten, nothing released",
			r.forgotten, r.released)
	}
}
