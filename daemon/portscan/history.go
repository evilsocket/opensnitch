//go:build linux

package portscan

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// A scan is reconnaissance: the source has learned which services listen, and
// what comes next, hours or days later, is an attempt on one of them. The
// alert is a notification, gone in seconds, and a question left unanswered
// leaves nothing behind. The history keeps each reported source, with its
// latest detection and what became of it, so that the user can still see it
// and block it once the alert is gone.

const (
	// HistoryRetention is how long a source stays in the history after its
	// latest detection, and so how long it can still be blocked after the
	// fact: long enough for the attempt that follows a scan by days.
	HistoryRetention = 7 * 24 * time.Hour
	// MaxHistory bounds the history. Each entry holds a ScanEvent, and a
	// decoy scan reports a source per decoy. When it is full, a new detection
	// takes the place of one without TCP evidence, or is not recorded (see
	// makeRoomLocked).
	MaxHistory = 512
)

// DetectionStatus is what became of a reported source.
type DetectionStatus int

const (
	// StatusDetected: reported under the policy "never", nothing asked.
	StatusDetected DetectionStatus = iota
	// StatusAsked: the user was asked, and has not answered yet.
	StatusAsked
	// StatusUnanswered: the question expired without an answer.
	StatusUnanswered
	// StatusIgnored: the user answered not to block.
	StatusIgnored
	// StatusRefused: the daemon did not block, and Reason says why.
	StatusRefused
	// StatusBlocked: a block was installed. It may since have expired.
	StatusBlocked
	// StatusReleased: the user released the block.
	StatusReleased
)

// String returns the identifier the user interface receives.
func (s DetectionStatus) String() string {
	switch s {
	case StatusDetected:
		return "detected"
	case StatusAsked:
		return "asked"
	case StatusUnanswered:
		return "unanswered"
	case StatusIgnored:
		return "ignored"
	case StatusRefused:
		return "refused"
	case StatusBlocked:
		return "blocked"
	case StatusReleased:
		return "released"
	default:
		return "unknown"
	}
}

// Detection is one source of the history.
type Detection struct {
	Addr netip.Addr
	// Scan is the latest detection of the source. Never nil.
	Scan *ScanEvent
	// FirstReported and LastReported are when the source was first and last
	// reported, by the daemon's wall clock.
	FirstReported time.Time
	LastReported  time.Time
	Status        DetectionStatus
	// Reason is the daemon's own words for a refusal.
	Reason string
}

// History is the bounded record of reported sources. It is safe for
// concurrent use.
type History struct {
	mu      sync.Mutex
	entries map[netip.Addr]*Detection
	now     func() time.Time
	// dropped counts the detections not recorded because the history was
	// full, since it was built.
	dropped uint64
}

// Dropped returns how many detections were not recorded, for lack of room,
// since the history was built.
func (h *History) Dropped() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dropped
}

// NewHistory returns an empty history.
func NewHistory() *History {
	return &History{entries: map[netip.Addr]*Detection{}, now: time.Now}
}

// Record adds a detection, or updates the source's entry with it.
//
// A detection without TCP evidence does not replace one with it: the source
// keeps its stronger record, with its own date, so that its retention runs
// from it. Otherwise the scanner itself, or anyone forging its address, could
// rewrite its entry with a few UDP datagrams into one that says its address
// may be forged, and make it unblockable without force; and refreshing the
// date would keep an old accusation alive, and looking new, for good. Only a
// question really asked is recorded on it.
func (h *History) Record(ev *ScanEvent, status DetectionStatus, reason string) {
	if ev == nil {
		return
	}
	addr := normalizeAddr(ev.Src)
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.pruneLocked(now)
	d, ok := h.entries[addr]
	if !ok {
		if len(h.entries) >= MaxHistory && !h.makeRoomLocked() {
			h.dropped++
			return
		}
		d = &Detection{Addr: addr, FirstReported: now}
		h.entries[addr] = d
	} else if d.Scan.HasTCPEvidence && !ev.HasTCPEvidence {
		if status == StatusAsked {
			d.Status, d.Reason = StatusAsked, ""
		}
		return
	}
	d.Scan = ev
	d.LastReported = now
	d.Status = status
	d.Reason = reason
}

// SetStatus records what became of a source already in the history, and
// reports whether it was there. A source the history has forgotten is not
// added back: there is no detection to show with it.
func (h *History) SetStatus(addr netip.Addr, status DetectionStatus, reason string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	d, ok := h.entries[normalizeAddr(addr)]
	if !ok {
		return false
	}
	d.Status = status
	d.Reason = reason
	return true
}

// expireAsked turns the questions left unanswered into StatusUnanswered.
func (h *History) expireAsked(addr netip.Addr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if d, ok := h.entries[normalizeAddr(addr)]; ok && d.Status == StatusAsked {
		d.Status = StatusUnanswered
	}
}

// Remove deletes the entry of addr, at the user's request, and reports
// whether there was one.
func (h *History) Remove(addr netip.Addr) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	addr = normalizeAddr(addr)
	_, ok := h.entries[addr]
	delete(h.entries, addr)
	return ok
}

// Lookup returns the entry of addr, if the history still holds it.
func (h *History) Lookup(addr netip.Addr) (Detection, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(h.now())
	d, ok := h.entries[normalizeAddr(addr)]
	if !ok {
		return Detection{}, false
	}
	return *d, true
}

// List returns at most limit entries, most recently reported first, and how
// many the history holds.
func (h *History) List(limit int) ([]Detection, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(h.now())
	out := make([]Detection, 0, len(h.entries))
	for _, d := range h.entries {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastReported.Equal(out[j].LastReported) {
			return out[i].LastReported.After(out[j].LastReported)
		}
		return out[i].Addr.Less(out[j].Addr)
	})
	total := len(out)
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, total
}

// Readopt takes over the entries of a previous history, so that a
// configuration reload, which rebuilds the monitor, does not forget them.
func (h *History) Readopt(entries []Detection) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(h.now())
	for i := range entries {
		d := entries[i]
		if d.Scan == nil {
			continue
		}
		d.Addr = normalizeAddr(d.Addr)
		if cur, ok := h.entries[d.Addr]; ok && !cur.LastReported.Before(d.LastReported) {
			continue
		}
		if _, ok := h.entries[d.Addr]; !ok && len(h.entries) >= MaxHistory && !h.makeRoomLocked() {
			h.dropped++
			continue
		}
		h.entries[d.Addr] = &d
	}
	h.pruneLocked(h.now())
}

func (h *History) pruneLocked(now time.Time) {
	for addr, d := range h.entries {
		if now.Sub(d.LastReported) > HistoryRetention {
			delete(h.entries, addr)
		}
	}
}

// makeRoomLocked frees one entry for a new detection, and reports whether
// it could. Only the oldest detection without TCP evidence that the user has
// not acted on (blocked or released) may go: such detections cost nothing to
// forge. A detection with TCP evidence is never pushed out by a newer one,
// since those can be forged too, with SYNs to closed ports: a scanner
// flooding the history after its scan, to erase it, would otherwise succeed
// at the pace the alert limiter allows. A full history therefore stops
// recording until entries age out, the monitor says so, and the alerts still
// go out; an attacker can fill it ahead of a scan, but not empty it of one.
func (h *History) makeRoomLocked() bool {
	var oldest *Detection
	for _, d := range h.entries {
		if d.Scan.HasTCPEvidence || d.Status == StatusBlocked || d.Status == StatusReleased {
			continue
		}
		if oldest == nil || d.LastReported.Before(oldest.LastReported) {
			oldest = d
		}
	}
	if oldest == nil {
		return false
	}
	delete(h.entries, oldest.Addr)
	return true
}
