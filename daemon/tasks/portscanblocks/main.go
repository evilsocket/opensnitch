// Package portscanblocks streams to the user interface the scan sources the
// daemon blocks and the ones it reported without blocking, so that a user can
// see what the daemon has done, judge it, release a block early or block a
// source after the fact.
//
// It is a task because TASK_START is how OpenSnitch already streams live data
// to the GUI: the reply stream stays open, keyed on the notification ID, and
// each tick pushes a fresh snapshot.
package portscanblocks

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks/base"
)

// Name is the task name the GUI sends in the TASK_START payload.
const Name = "portscan-blocks"

const (
	// DefaultInterval is how often a snapshot is pushed. The GUI counts down
	// between pushes, so this sets how fast an arrival or a release shows up.
	DefaultInterval = 2 * time.Second

	// MinInterval bounds what the GUI may ask for: the interval comes from a
	// socket the daemon does not authenticate, and each tick marshals a snapshot.
	MinInterval = 500 * time.Millisecond
	// MaxInterval keeps a mistyped value from looking like a hung view.
	MaxInterval = 5 * time.Minute

	// MaxEntries bounds one snapshot. Block.MaxBlockedSources may reach 65536 --
	// a decoy scan fills it -- and a view shows a few dozen rows; the count of
	// what was left out is sent instead.
	MaxEntries = 512
	// MaxDetections bounds the detections of one snapshot, as MaxEntries
	// bounds the blocks. The daemon's history holds at most as many.
	MaxDetections = 512
)

// Blocked is one entry as the user interface receives it.
type Blocked struct {
	// Addr is the blocked address, in its canonical textual form.
	Addr string `json:"addr"`
	// Reason is the daemon's own words for why it was blocked.
	Reason string `json:"reason"`
	// ExpiresAt is the wall-clock expiry, in Unix seconds.
	ExpiresAt int64 `json:"expires_at"`
	// BlockedAt is when the block was installed or last extended, in Unix
	// seconds: the user interface lists blocks and detections together, most
	// recent first. Absent from daemons that predate it.
	BlockedAt int64 `json:"blocked_at,omitempty"`
	// Remaining is how many seconds the daemon believes are left, sent with
	// ExpiresAt because the GUI may be on another host with another clock.
	Remaining int64 `json:"remaining"`
	// Stuck marks a block whose release the firewall refused: past its expiry
	// and still installed. The GUI must not show it as about to expire.
	Stuck bool `json:"stuck,omitempty"`
}

// Detected is a source the daemon reported as scanning and does not block
// right now: the question expired or was answered no, the policy did not
// block, or a block ended. It is kept for a while (see portscan.History), so
// that the user can still see the scan and block the source after the fact.
type Detected struct {
	// Addr is the source address, in its canonical textual form.
	Addr string `json:"addr"`
	// Method and MethodDetail are the PortScan fields of the same names, for
	// the latest detection.
	Method       string `json:"method"`
	MethodDetail string `json:"method_detail"`
	// Status is what became of the source: detected, asked, unanswered,
	// ignored, refused, released, or ended (a block that ended other than by a
	// release: it expired, was evicted by the cap, or was not carried over).
	Status string `json:"status"`
	// Reason is the daemon's own words for a refusal.
	Reason string `json:"reason,omitempty"`
	// FirstReported and LastReported are Unix seconds.
	FirstReported int64 `json:"first_reported"`
	LastReported  int64 `json:"last_reported"`
	// Eligible reports that the detection is enough to block the source.
	// Blocking one that is not takes "force": its address may be forged.
	Eligible bool `json:"eligible"`
	// Exempt marks a source on the never-block list: it cannot be blocked.
	Exempt bool `json:"exempt,omitempty"`
}

// Snapshot is the payload pushed on each tick.
type Snapshot struct {
	// Blocks is the list, most recently blocked first, bounded by MaxEntries.
	Blocks []Blocked `json:"blocks"`
	// Total is how many blocks the daemon holds, before any truncation.
	Total int `json:"total"`
	// Omitted is Total minus the number sent.
	Omitted int `json:"omitted"`
	// Detections are the reported sources not blocked right now, most
	// recently reported first, bounded by MaxDetections. Absent, with
	// DetectionsUnchanged, when they are what this stream last sent: a full
	// history is a quarter of a megabyte, and it changes far less often than
	// every tick.
	Detections *[]Detected `json:"detections,omitempty"`
	// DetectionsUnchanged says the receiver should keep the detections this
	// stream sent last.
	DetectionsUnchanged bool `json:"detections_unchanged,omitempty"`
	// DetectionsTotal is how many there are, before any truncation.
	DetectionsTotal int `json:"detections_total"`
	// CanBlock reports whether the daemon can install a block: false under
	// the policy "never", or without a firewall backend.
	CanBlock bool `json:"can_block"`
}

// Lister is the subset of the port scan monitor this task needs, an interface
// so that neither this package nor daemon/ui imports daemon/portscan.
type Lister interface {
	// BlockedList returns at most limit blocks, most recent first, and the
	// total. It must be safe to call from another goroutine and return a slice the
	// caller may keep. It returns an error, not an empty list, when there is no
	// block table to read: "nothing is blocked" and "nothing is watching" look
	// identical in a table and mean opposite things.
	BlockedList(limit int) ([]Blocked, int, error)
}

// DetectionLister is an optional Lister that also lists the reported sources
// it does not block, and says whether it can block at all.
type DetectionLister interface {
	DetectionList(limit int) (list []Detected, total int, canBlock bool, err error)
}

// Monitor pushes a snapshot of the blocks and detections on a ticker.
type Monitor struct {
	base.TaskBase
	mu       sync.RWMutex
	ticker   *time.Ticker
	lister   Lister
	interval time.Duration
	// sent records the detections last sent on this stream, so an unchanged
	// list is not sent again. Only the goroutine Start runs touches it.
	sent *sentDetections
	// stopped is set by Stop and read by Start: the task manager runs Start in a
	// goroutine of its own, so a TASK_STOP right behind a TASK_START can arrive
	// first, and Start must then not run at all.
	stopped bool
}

// New returns a task that lists what lister holds.
//
// config is the Data field of the TaskNotification, and may be nil: the GUI is
// allowed to ask for the list without naming an interval.
func New(lister Lister, config interface{}, stopOnDisconnect bool) (*Monitor, error) {
	if lister == nil {
		// Not "an empty list". A GUI told the block table is empty when
		// detection is simply not running would state, in the one view the
		// user opens to check, that nothing is blocked -- while rules from a
		// previous run may still be installed.
		return nil, fmt.Errorf("port scan detection is not running")
	}
	interval, err := parseInterval(config)
	if err != nil {
		return nil, err
	}
	return &Monitor{
		TaskBase: base.TaskBase{
			Name:             Name,
			Results:          make(chan interface{}),
			Errors:           make(chan error),
			StopOnDisconnect: stopOnDisconnect,
		},
		lister:   lister,
		interval: interval,
	}, nil
}

// parseInterval reads the optional interval out of the task configuration.
// Anything it cannot make sense of is an error, not a silent fallback to the
// default.
func parseInterval(config interface{}) (time.Duration, error) {
	if config == nil {
		return DefaultInterval, nil
	}
	conf, ok := config.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("%s: expected an object in the task data, got %T", Name, config)
	}
	raw, present := conf["interval"]
	if !present {
		return DefaultInterval, nil
	}
	text, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("%s: \"interval\" must be a string, got %T", Name, raw)
	}
	if text == "" {
		return DefaultInterval, nil
	}
	interval, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid interval %q: %w", Name, text, err)
	}
	if interval < MinInterval || interval > MaxInterval {
		return 0, fmt.Errorf("%s: interval %s is outside %s..%s", Name, interval, MinInterval, MaxInterval)
	}
	return interval, nil
}

// snapshot builds the payload. It is separate from the loop so that the shape
// sent to the GUI can be tested without a ticker.
func (m *Monitor) snapshot() (Snapshot, error) {
	all, total, err := m.lister.BlockedList(MaxEntries)
	if err != nil {
		return Snapshot{}, err
	}
	if len(all) > MaxEntries {
		all = all[:MaxEntries]
	}
	if total < len(all) {
		total = len(all)
	}
	snap := Snapshot{Total: total, Omitted: total - len(all)}
	// Never nil: encoding/json writes nil as "null", and a GUI that reads
	// "blocks" expecting a list would have to special-case it. An empty table
	// is [].
	snap.Blocks = make([]Blocked, 0, len(all))
	snap.Blocks = append(snap.Blocks, all...)
	none := []Detected{}
	snap.Detections = &none
	if dl, ok := m.lister.(DetectionLister); ok {
		found, total, canBlock, err := dl.DetectionList(MaxDetections)
		if err != nil {
			return Snapshot{}, err
		}
		if len(found) > MaxDetections {
			found = found[:MaxDetections]
		}
		if total < len(found) {
			total = len(found)
		}
		list := append([]Detected{}, found...)
		snap.DetectionsTotal = total
		snap.CanBlock = canBlock
		if m.sent != nil && m.sent.total == total && reflect.DeepEqual(m.sent.list, list) {
			snap.Detections = nil
			snap.DetectionsUnchanged = true
		} else {
			snap.Detections = &list
			m.sent = &sentDetections{list: list, total: total}
		}
	}
	return snap, nil
}

type sentDetections struct {
	list  []Detected
	total int
}

// Start begins pushing snapshots.
func (m *Monitor) Start(ctx context.Context, cancel context.CancelFunc) error {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		cancel()
		return nil
	}
	m.Ctx = ctx
	m.Cancel = cancel
	m.ticker = time.NewTicker(m.interval)
	ticker := m.ticker
	m.mu.Unlock()

	go func() {
		defer ticker.Stop()
		for {
			data, err := m.encode()
			if err != nil {
				// Reported rather than dropped. A view that silently stopped
				// updating would show a block table frozen at whatever it held
				// when detection went away -- addresses the user believes are
				// still blocked, and are not.
				if !m.sendError(ctx, err) {
					goto Exit
				}
			} else if !m.sendResult(ctx, data) {
				goto Exit
			}
			select {
			case <-ctx.Done():
				goto Exit
			case <-ticker.C:
			}
		}
	Exit:
		log.Debug("[tasks.%s] stopped", Name)
	}()
	return nil
}

// encode produces the JSON the GUI receives.
func (m *Monitor) encode() (string, error) {
	snap, err := m.snapshot()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// sendResult delivers one snapshot, or reports that the task is over. A plain
// channel send would block for ever once the reader is gone.
func (m *Monitor) sendResult(ctx context.Context, v interface{}) bool {
	select {
	case m.TaskBase.Results <- v:
		return true
	case <-ctx.Done():
		return false
	}
}

// sendError is sendResult for the failure channel, and exists for the same
// reason.
func (m *Monitor) sendError(ctx context.Context, err error) bool {
	select {
	case m.TaskBase.Errors <- err:
		return true
	case <-ctx.Done():
		return false
	}
}

// Pause is a no-op: a snapshot is cheap and stateless, so there is nothing to
// suspend that stopping the task does not already do.
func (m *Monitor) Pause() error { return nil }

// Resume is the counterpart of Pause, and equally has nothing to do.
func (m *Monitor) Resume() error { return nil }

// Stop ends the task.
func (m *Monitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopped = true
	if m.ticker != nil {
		m.ticker.Stop()
	}
	if m.Cancel != nil {
		m.Cancel()
	}
	return nil
}

// Results returns the channel snapshots are pushed on.
func (m *Monitor) Results() <-chan interface{} { return m.TaskBase.Results }

// Errors returns the channel failures are pushed on.
func (m *Monitor) Errors() <-chan error { return m.TaskBase.Errors }
