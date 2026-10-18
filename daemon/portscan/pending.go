//go:build linux

package portscan

import (
	crand "crypto/rand"
	"math/rand/v2"
	"net/netip"
	"sort"
	"sync"
)

// pendingReports holds crossings the alert limiter refused, so they are
// reported when the budget allows instead of lost: a scanner that has finished
// sends no further probe to be named by.
//
// nmap -D sends the same scan from forged addresses, so every decoy crosses
// with the real scanner's score and port count, and nothing tells them apart.
// Entries are kept in a total order (rank, tie), tie drawn at random when an
// entry is first queued:
//
//   - a full queue drops its lowest entry, or refuses a newcomer lower still;
//     among equal ranks that is a fair draw including the newcomer, so arriving
//     last is no worse than arriving first;
//   - the drain takes the highest entry, so ties come out in an order the
//     attacker chose neither by address nor by arrival.
//
// The order is a sorted slice: an insertion moves at most maxPendingReports
// keys, a few microseconds under the lock.
type pendingReports struct {
	mu    sync.Mutex
	byID  map[netip.Addr]*pendingEntry
	order []*pendingEntry // ascending (rank, tie)
	rng   *rand.ChaCha8
}

type pendingEntry struct {
	ev   *ScanEvent
	rank uint64
	tie  uint64
}

func (a *pendingEntry) less(b *pendingEntry) bool {
	if a.rank != b.rank {
		return a.rank < b.rank
	}
	return a.tie < b.tie
}

// maxPendingReports bounds the queue: about 22 hours of alerts at the default
// three a minute, a few hundred bytes per entry. The limiter decides how fast
// alerts are shown; this bound decides how many decoys it takes to push the
// real scanner out.
const maxPendingReports = 4096

func newPendingReports() *pendingReports {
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		// crypto/rand does not fail on Linux; a fixed seed would still be a
		// working queue, only one whose tie order an attacker could predict.
		panic("portscan: crypto/rand: " + err.Error())
	}
	return &pendingReports{byID: map[netip.Addr]*pendingEntry{}, rng: rand.NewChaCha8(seed)}
}

// queueRank orders crossings by how much they cost to produce: score, then the
// distinct ports touched, clamped to the span observed, so claiming a thousand
// ports means sending to a thousand. Score alone is capped, and seventeen forged
// SYNs reach the cap.
func queueRank(ev *ScanEvent) uint64 {
	return uint64(ev.Score)<<32 | uint64(ev.DistinctPorts)
}

// position is where e sits, or would be inserted, in p.order.
func (p *pendingReports) position(e *pendingEntry) int {
	return sort.Search(len(p.order), func(i int) bool { return !p.order[i].less(e) })
}

func (p *pendingReports) insert(e *pendingEntry) {
	i := p.position(e)
	p.order = append(p.order, nil)
	copy(p.order[i+1:], p.order[i:])
	p.order[i] = e
	p.byID[e.ev.Src] = e
}

func (p *pendingReports) remove(e *pendingEntry) {
	i := p.position(e)
	for i < len(p.order) && p.order[i] != e {
		i++
	}
	if i == len(p.order) {
		return
	}
	copy(p.order[i:], p.order[i+1:])
	p.order[len(p.order)-1] = nil
	p.order = p.order[:len(p.order)-1]
	delete(p.byID, e.ev.Src)
}

// add queues an event, replacing any earlier one for the same source.
func (p *pendingReports) add(ev *ScanEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := &pendingEntry{ev: ev, rank: queueRank(ev)}
	if old, known := p.byID[ev.Src]; known {
		// A replacement keeps its draw: re-queueing must not be a way to
		// re-roll it.
		e.tie = old.tie
		p.remove(old)
		p.insert(e)
		return
	}
	e.tie = p.rng.Uint64()
	if len(p.order) >= maxPendingReports {
		if e.less(p.order[0]) {
			return
		}
		p.remove(p.order[0])
	}
	p.insert(e)
}

// forget drops a source, for when it has been reported or has gone away.
func (p *pendingReports) forget(addr netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.byID[addr]; ok {
		p.remove(e)
	}
}

// takeIf removes and returns the highest entry, but only if allow agrees;
// allow runs under the queue lock, once an event is known to exist, so a
// limiter slot is never spent on an empty queue.
func (p *pendingReports) takeIf(allow func() bool) *ScanEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.order) == 0 || !allow() {
		return nil
	}
	e := p.order[len(p.order)-1]
	p.remove(e)
	return e.ev
}

// take removes and returns up to n queued events, in drain order.
func (p *pendingReports) take(n int) []*ScanEvent {
	var out []*ScanEvent
	for len(out) < n {
		ev := p.takeIf(func() bool { return true })
		if ev == nil {
			break
		}
		out = append(out, ev)
	}
	return out
}

func (p *pendingReports) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.order)
}
