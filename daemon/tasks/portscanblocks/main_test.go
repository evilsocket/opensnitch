package portscanblocks

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLister stands in for the port scan monitor.
type fakeLister struct {
	mu   sync.Mutex
	list []Blocked
	err  error
	// calls counts snapshots taken, so a test can prove the task re-reads the
	// source rather than answering from something it captured once.
	calls int
	// asked is the largest limit it was asked for.
	asked int
}

func (f *fakeLister) BlockedList(limit int) ([]Blocked, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if limit > f.asked {
		f.asked = limit
	}
	if f.err != nil {
		return nil, 0, f.err
	}
	list := f.list
	if limit >= 0 && len(list) > limit {
		list = list[:limit]
	}
	return list, len(f.list), nil
}

func (f *fakeLister) set(list []Blocked, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list, f.err = list, err
}

func (f *fakeLister) seen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func entries(n int) []Blocked {
	out := make([]Blocked, n)
	for i := range out {
		out[i] = Blocked{
			Addr:      fmt.Sprintf("192.0.2.%d", i%256),
			Reason:    "automatic policy",
			ExpiresAt: int64(1700000000 + i),
			Remaining: int64(i),
		}
	}
	return out
}

func newTask(t *testing.T, l Lister, config interface{}) *Monitor {
	t.Helper()
	m, err := New(l, config, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestNewRefusesAMissingMonitor(t *testing.T) {
	// The GUI may ask for the list while detection is off, which is the
	// default. The refusal has to be an error the user sees, not an empty
	// table that says nothing is blocked.
	if _, err := New(nil, nil, true); err == nil {
		t.Fatal("New accepted a nil lister")
	}
}

func TestIntervalParsing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config interface{}
		want   time.Duration
		bad    bool
	}{
		{name: "absent config", config: nil, want: DefaultInterval},
		{name: "no interval key", config: map[string]interface{}{}, want: DefaultInterval},
		{name: "empty interval", config: map[string]interface{}{"interval": ""}, want: DefaultInterval},
		{name: "explicit", config: map[string]interface{}{"interval": "3s"}, want: 3 * time.Second},
		{name: "lower bound", config: map[string]interface{}{"interval": MinInterval.String()}, want: MinInterval},
		{name: "upper bound", config: map[string]interface{}{"interval": MaxInterval.String()}, want: MaxInterval},
		{name: "too fast", config: map[string]interface{}{"interval": "1ms"}, bad: true},
		{name: "too slow", config: map[string]interface{}{"interval": "6h"}, bad: true},
		{name: "not a duration", config: map[string]interface{}{"interval": "soon"}, bad: true},
		{name: "not a string", config: map[string]interface{}{"interval": 5}, bad: true},
		{name: "not an object", config: "3s", bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseInterval(tc.config)
			if tc.bad {
				if err == nil {
					t.Fatalf("parseInterval(%#v) accepted it, got %s", tc.config, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInterval(%#v): %v", tc.config, err)
			}
			if got != tc.want {
				t.Fatalf("parseInterval(%#v) = %s, want %s", tc.config, got, tc.want)
			}
		})
	}
}

// A bad interval must not start a task. Accepting it and falling back to the
// default would produce load nobody asked for, from a view that believes it
// asked for something else.
func TestNewRejectsABadInterval(t *testing.T) {
	if _, err := New(&fakeLister{}, map[string]interface{}{"interval": "1ns"}, true); err == nil {
		t.Fatal("New accepted an out-of-range interval")
	}
}

func TestSnapshotIsBounded(t *testing.T) {
	l := &fakeLister{}
	l.set(entries(MaxEntries+37), nil)
	snap, err := newTask(t, l, nil).snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snap.Blocks) != MaxEntries {
		t.Fatalf("sent %d entries, want %d", len(snap.Blocks), MaxEntries)
	}
	if snap.Total != MaxEntries+37 {
		t.Fatalf("Total = %d, want %d", snap.Total, MaxEntries+37)
	}
	if snap.Omitted != 37 {
		t.Fatalf("Omitted = %d, want 37", snap.Omitted)
	}
}

func TestSnapshotUnderTheBoundOmitsNothing(t *testing.T) {
	l := &fakeLister{}
	l.set(entries(3), nil)
	snap, err := newTask(t, l, nil).snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snap.Blocks) != 3 || snap.Total != 3 || snap.Omitted != 0 {
		t.Fatalf("got %d/%d omitted %d, want 3/3 omitted 0",
			len(snap.Blocks), snap.Total, snap.Omitted)
	}
}

// An empty table must serialise as [], not null: the GUI reads "blocks" as a
// list and would otherwise need a special case for the ordinary state of a
// machine nobody is scanning.
func TestEmptyTableEncodesAsAList(t *testing.T) {
	data, err := newTask(t, &fakeLister{}, nil).encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(data, `"blocks":[]`) {
		t.Fatalf("encoded empty table as %s", data)
	}
	var back Snapshot
	if err := json.Unmarshal([]byte(data), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Blocks == nil || len(back.Blocks) != 0 {
		t.Fatalf("decoded blocks = %#v", back.Blocks)
	}
}

// The fields the view renders must survive the round trip, because the whole
// path between the daemon and the table is this one JSON document.
func TestSnapshotRoundTrip(t *testing.T) {
	l := &fakeLister{}
	want := Blocked{
		Addr:      "2001:db8::66",
		Reason:    "confirmed by the user",
		ExpiresAt: 1758648000,
		Remaining: 14012,
	}
	l.set([]Blocked{want}, nil)
	data, err := newTask(t, l, nil).encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var back Snapshot
	if err := json.Unmarshal([]byte(data), &back); err != nil {
		t.Fatalf("unmarshal %s: %v", data, err)
	}
	if len(back.Blocks) != 1 || back.Blocks[0] != want {
		t.Fatalf("round trip gave %#v, want %#v", back.Blocks, want)
	}
}

func TestStartPushesSnapshotsAndFollowsTheSource(t *testing.T) {
	l := &fakeLister{}
	l.set(entries(1), nil)
	m := newTask(t, l, map[string]interface{}{"interval": MinInterval.String()})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, cancel); err != nil {
		t.Fatalf("Start: %v", err)
	}

	first := receive(t, m)
	if first.Total != 1 {
		t.Fatalf("first snapshot Total = %d, want 1", first.Total)
	}

	// The list is on screen while the block table changes underneath it.
	l.set(entries(4), nil)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("the task never reported the new block table")
		default:
		}
		if snap := receive(t, m); snap.Total == 4 {
			break
		}
	}
	if l.seen() < 2 {
		t.Fatalf("the task took %d snapshots; it is not re-reading the source", l.seen())
	}
}

// Detection stopping while the list is on screen must reach the user as an error,
// not as an empty table.
func TestAFailingListerIsReported(t *testing.T) {
	l := &fakeLister{}
	l.set(nil, fmt.Errorf("port scan detection is not running"))
	m := newTask(t, l, map[string]interface{}{"interval": MinInterval.String()})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, cancel); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case err := <-m.Errors():
		if err == nil || !strings.Contains(err.Error(), "not running") {
			t.Fatalf("reported %v", err)
		}
	case data := <-m.Results():
		t.Fatalf("a stopped monitor produced a block table: %v", data)
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was reported")
	}
}

// Stop must end the goroutine even though nobody is reading the channel.
//
// The plain channel send the sibling tasks use blocks forever in that case, so
// every view the user ever opened would leave a goroutine and a live ticker
// behind. This test holds the select this task uses instead.
func TestStopEndsTheTaskWithNoReader(t *testing.T) {
	before := runtime.NumGoroutine()
	l := &fakeLister{}
	l.set(entries(2), nil)
	m := newTask(t, l, map[string]interface{}{"interval": MinInterval.String()})

	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Start(ctx, cancel); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Let it reach the blocking send with no reader on the other side.
	time.Sleep(50 * time.Millisecond)
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines %d -> %d after Stop; the task did not exit",
		before, runtime.NumGoroutine())
}

func receive(t *testing.T, m *Monitor) Snapshot {
	t.Helper()
	select {
	case v := <-m.Results():
		data, ok := v.(string)
		if !ok {
			t.Fatalf("result is %T, not the string the task manager forwards", v)
		}
		var snap Snapshot
		if err := json.Unmarshal([]byte(data), &snap); err != nil {
			t.Fatalf("unmarshal %s: %v", data, err)
		}
		return snap
	case err := <-m.Errors():
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no snapshot arrived")
	}
	return Snapshot{}
}

// TestTheCapIsAskedOfTheLister: the task shows MaxEntries, and it must ask for
// no more. Otherwise the adapter would convert every block -- up to 65536,
// 17 ms per refresh under the manager's lock -- before the task dropped all
// but 512.
func TestTheCapIsAskedOfTheLister(t *testing.T) {
	l := &fakeLister{list: entries(MaxEntries + 100)}
	m, err := New(l, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := m.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if l.asked != MaxEntries {
		t.Fatalf("the lister was asked for %d entries, want %d", l.asked, MaxEntries)
	}
	if len(snap.Blocks) != MaxEntries || snap.Total != MaxEntries+100 || snap.Omitted != 100 {
		t.Fatalf("snapshot of %d blocks, total %d, omitted %d", len(snap.Blocks), snap.Total, snap.Omitted)
	}
}

// TestAStopBeforeStartLeavesNothingRunning: the task manager runs Start in a
// goroutine and Stop directly, so a TASK_STOP right behind a TASK_START can
// come first. Stop found nothing to cancel, the manager forgot the task, and
// Start then pushed snapshots for ever -- about one task in two over 2000
// start/stop pairs, out of reach of any later stop or disconnect.
func TestAStopBeforeStartLeavesNothingRunning(t *testing.T) {
	m, err := New(&fakeLister{}, map[string]interface{}{"interval": "500ms"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Start(ctx, cancel); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("a task stopped before it started is running")
	}
	select {
	case v := <-m.Results():
		t.Fatalf("a task stopped before it started pushed %v", v)
	case <-time.After(700 * time.Millisecond):
	}
}

type detectingLister struct {
	list []Detected
}

func (l *detectingLister) BlockedList(int) ([]Blocked, int, error) { return nil, 0, nil }
func (l *detectingLister) DetectionList(int) ([]Detected, int, bool, error) {
	return l.list, len(l.list), true, nil
}

// TestUnchangedDetectionsAreNotSentAgain: a full history is a quarter of a
// megabyte; a stream sends it when it changes, not on every tick.
func TestUnchangedDetectionsAreNotSentAgain(t *testing.T) {
	l := &detectingLister{list: []Detected{{Addr: "192.0.2.9", Status: "unanswered"}}}
	m, err := New(l, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := m.snapshot()
	if first.Detections == nil || len(*first.Detections) != 1 || first.DetectionsUnchanged {
		t.Fatalf("first snapshot: %+v", first)
	}
	second, _ := m.snapshot()
	if second.Detections != nil || !second.DetectionsUnchanged || second.DetectionsTotal != 1 {
		t.Fatalf("unchanged detections were sent again: %+v", second)
	}
	data, _ := json.Marshal(second)
	if strings.Contains(string(data), `"detections":`) {
		t.Fatalf("the JSON still carries them: %s", data)
	}
	l.list = append(l.list, Detected{Addr: "192.0.2.10", Status: "ignored"})
	third, _ := m.snapshot()
	if third.Detections == nil || len(*third.Detections) != 2 || third.DetectionsUnchanged {
		t.Fatalf("a change was not sent: %+v", third)
	}
	l.list = l.list[:0]
	empty, _ := m.snapshot()
	data, _ = json.Marshal(empty)
	if !strings.Contains(string(data), `"detections":[]`) {
		t.Fatalf("an emptied history must be sent as []: %s", data)
	}
}

type totalLister struct {
	list  []Detected
	total int
}

func (l *totalLister) BlockedList(int) ([]Blocked, int, error) { return nil, 0, nil }
func (l *totalLister) DetectionList(int) ([]Detected, int, bool, error) {
	return l.list, l.total, true, nil
}

// TestAChangedTotalIsSent: past MaxDetections the list sent can stay the same
// while the total changes; the total is part of what was sent.
func TestAChangedTotalIsSent(t *testing.T) {
	l := &totalLister{list: []Detected{{Addr: "192.0.2.9"}}, total: 600}
	m, _ := New(l, nil, false)
	m.snapshot()
	l.total = 601
	snap, _ := m.snapshot()
	if snap.DetectionsUnchanged || snap.Detections == nil || snap.DetectionsTotal != 601 {
		t.Fatalf("a changed total was not sent: %+v", snap)
	}
}
