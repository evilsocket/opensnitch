package procmon

import (
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
)

var (
	// EventsCache is the cache of processes
	EventsCache       *EventsStore
	eventsCacheTicker *time.Ticker

	// When we receive an Exit event, we'll delete it from cache.
	// This TTL defines how much time we retain a PID on cache, before we receive
	// an Exit event.
	pidTTL = 20 // seconds
)

func init() {
	EventsCache = NewEventsStore()
	go monitorEventsCache()
}

// ProcessEvent represents an process event
type ProcessEvent struct {
	Filename string
	Args     string
	Comm     string
	PID      uint64
	PPID     uint64
	UID      uint64
}

// ExecEventItem represents an item of the cache
type ExecEventItem struct {
	//sync.RWMutex
	Proc     Process
	LastSeen int64
	TTL      int32
}

func (e *ExecEventItem) isValid() bool {
	lastSeen := time.Now().Sub(
		time.Unix(0, e.LastSeen),
	)
	return int(lastSeen.Seconds()) < pidTTL
}

//EventsStore is the cache of exec events
type EventsStore struct {
	eventByPID       map[int]ExecEventItem
	checksums        map[string]uint
	mu               *sync.RWMutex
	checksumsEnabled bool
}

// NewEventsStore creates a new store of events.
func NewEventsStore() *EventsStore {
	if eventsCacheTicker != nil {
		eventsCacheTicker.Stop()
	}
	eventsCacheTicker = time.NewTicker(10 * time.Second)

	return &EventsStore{
		mu:         &sync.RWMutex{},
		checksums:  make(map[string]uint, 500),
		eventByPID: make(map[int]ExecEventItem, 500),
	}
}

// Add adds a new process to cache.
// If computing checksums is enabled, new checksums will be computed if needed,
// or reused existing ones otherwise.
func (e *EventsStore) Add(proc *Process) {
	log.Debug("[cache] EventsStore.Add() %d, %s", proc.ID, proc.Path)
	// Add the item to cache ASAP,
	// then calculate the checksums if needed.
	e.UpdateItem(proc)
	if e.GetComputeChecksums() {
		if e.ComputeChecksums(proc) {
			e.UpdateItem(proc)
		}
	}
	log.Debug("[cache] EventsStore.Add() finished")
}

// UpdateItem updates a cache item
func (e *EventsStore) UpdateItem(proc *Process) {
	log.Debug("[cache] updateItem() updating events store (total: %d), pid: %d, path: %s", e.Len(), proc.ID, proc.Path)
	if proc.Path == "" {
		return
	}
	e.mu.Lock()
	ev := ExecEventItem{
		Proc:     *proc,
		LastSeen: time.Now().UnixNano(),
	}
	e.eventByPID[proc.ID] = ev
	e.mu.Unlock()
}

// ReplaceItem replaces an existing process with a new one.
func (e *EventsStore) ReplaceItem(oldProc, newProc *Process) {
	log.Debug("[event inCache, replacement] new: %d, %s -> inCache: %d -> %s", newProc.ID, newProc.Path, oldProc.ID, oldProc.Path)
	// Note: in rare occasions, the process being replaced is the older one.
	// if oldProc.Starttime > newProc.Starttime {}
	//

	newProc.PPID = oldProc.ID
	e.UpdateItem(newProc)

	if newProc.ChecksumsCount() == 0 {
		e.ComputeChecksums(newProc)
		e.UpdateItem(newProc)
	}

	if len(oldProc.Tree) == 0 {
		oldProc.GetParent()
		oldProc.BuildTree()
		e.UpdateItem(newProc)
	}

	// TODO: work on improving the process tree (specially with forks/clones*)
	if len(newProc.Tree) == 0 {
		newProc.Parent = oldProc
		newProc.BuildTree()
		e.UpdateItem(newProc)
	}
}

// Update ...
func (e *EventsStore) Update(oldProc, proc *Process) {
	log.Debug("[cache Update old] %d in cache -> %s", oldProc.ID, oldProc.Path)

	update := false
	updateOld := false

	// forked process. Update cache.
	// execEvent -> pid: 12345, /usr/bin/exec-wrapper
	// execEvent -> pid: 12345, /usr/bin/telnet
	if proc != nil && (proc.ID == oldProc.ID && proc.Path != oldProc.Path) {
		e.ReplaceItem(oldProc, proc)
		return
	}

	if len(oldProc.Tree) == 0 {
		oldProc.GetParent()
		oldProc.BuildTree()
		updateOld = true
	}

	if proc != nil && (len(oldProc.Tree) > 0 && len(proc.Tree) == 0 && oldProc.ID == proc.ID) {
		proc.Tree = oldProc.Tree
		update = true
	}

	if updateOld {
		log.Debug("[cache] Update end, updating oldProc: %d, %s, %v", oldProc.ID, oldProc.Path, oldProc.Tree)
		e.UpdateItem(oldProc)
	}
	if update {
		log.Debug("[cache] Update end, updating newProc: %d, %s, %v", proc.ID, proc.Path, proc.Tree)
		e.UpdateItem(proc)
	}
}

func (e *EventsStore) needsUpdate(cachedProc, proc *Process) bool {
	cachedProc.RLock()
	defer cachedProc.RUnlock()

	// check if this PID has replaced the PPID:
	// systemd, pid:1234 -> curl, pid:1234 -> curl (i.e.: pid 1234) opens x.x.x.x:443
	// Without this, we would display for example "systemd is connecting to x.x.x.x:443",
	// instead of "curl is connecting to ..."
	// The previous pid+path will still exist as parent of the new child, in proc.Parent
	if proc != nil && (proc.ID == cachedProc.ID && proc.Path != cachedProc.Path) {
		return true
	}

	sumsCount := cachedProc.ChecksumsCount()

	if proc != nil && sumsCount > 0 && cachedProc.IsAlive() {
		return false
	}

	if cachedProc != nil && sumsCount == 0 {
		return true
	}

	if proc != nil && len(proc.Tree) == 0 {
		return true
	}
	if cachedProc != nil && len(cachedProc.Tree) == 0 {
		return true
	}

	return false
}

// IsInStore checks if a PID is in the store.
// If the PID is in cache, we may need to update it if the PID
// is reusing the PID of the parent.
func (e *EventsStore) IsInStore(key int, proc *Process) (item ExecEventItem, needsUpdate, found bool) {

	item, found = e.IsInStoreByPID(key)
	if !found {
		return
	}
	if found && e.needsUpdate(&item.Proc, proc) {
		needsUpdate = true
		return
	}

	log.Debug("[cache] Event found by PID: %d, %s", key, item.Proc.Path)

	return
}

// IsInStoreByPID checks if a pid exists in cache.
func (e *EventsStore) IsInStoreByPID(key int) (item ExecEventItem, found bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	item, found = e.eventByPID[key]

	if !found {
		return
	}

	item.LastSeen = time.Now().UnixNano()

	return
}

// Len returns the number of items in cache.
func (e *EventsStore) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.eventByPID)
}

// Delete schedules an item to be deleted from cache.
func (e *EventsStore) Delete(key int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	ev, found := e.eventByPID[key]
	if !found {
		return
	}
	if !ev.Proc.IsAlive() {
		delete(e.eventByPID, key)
	}
}

// DeleteOldItems deletes items that have exited and exceeded the TTL.
// Keeping them in cache for a short period of time sometimes helps to
// link some connections to processes.
// Alived processes are not deleted.
func (e *EventsStore) DeleteOldItems() {
	e.mu.Lock()
	defer e.mu.Unlock()

	log.Debug("[cache] deleting old events, total byPID: %d", len(e.eventByPID))
	for k, item := range e.eventByPID {
		if !item.isValid() && !item.Proc.IsAlive() {
			delete(e.eventByPID, k)
		}
	}
}

// ComputeChecksums obtains the checksums of the process
func (e *EventsStore) ComputeChecksums(proc *Process) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.checksumsEnabled || proc != nil && proc.IsAlive() && proc.ChecksumsCount() > 0 {
		log.Debug("[cache] ComputeChecksums, already hashed: %s -> %v", proc.Path, proc.Checksums)
		return false
	}
	proc.ComputeChecksums(e.checksums)

	return true
}

// AddChecksumHash adds a new hash algorithm to compute checksums
func (e *EventsStore) AddChecksumHash(hash string) {
	e.mu.Lock()
	e.checksums[hash]++
	e.mu.Unlock()
}

// DelChecksumHash deletes a hash algorithm from the list
func (e *EventsStore) DelChecksumHash(hash string) {
	e.mu.Lock()
	if _, found := e.checksums[hash]; found {
		e.checksums[hash]--
	}
	e.mu.Unlock()
}

// SetComputeChecksums configures if we compute checksums of processes.
// They will  be disabled if there's no rule that requires checksums.
// When enabling this functionality, some already stored process may don't have
// the checksums computed yet, so when enabling compute them.
func (e *EventsStore) SetComputeChecksums(compute bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if compute == e.checksumsEnabled {
		log.Debug("SetComputeChecksums(), no changes (%v, %v)", e.checksumsEnabled, compute)
		return
	}
	e.checksumsEnabled = compute
	if !compute {
		log.Debug("SetComputeChecksums() disabled, deleting saved checksums")
		for _, item := range e.eventByPID {
			// XXX: reset saved checksums? or keep them in cache?
			item.Proc.ResetChecksums()
		}
		return
	}
	log.Debug("SetComputeChecksums() enabled, recomputing cached checksums")
	for _, item := range e.eventByPID {
		if item.Proc.ChecksumsCount() == 0 {
			item.Proc.ComputeChecksums(e.checksums)
		}
	}
}

// DisableChecksums disables computing checksums functionality.
func (e *EventsStore) DisableChecksums() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.checksumsEnabled = false
	e.checksums = make(map[string]uint)
}

// GetComputeChecksums returns if computing checksums is enabled or not.
// Disabled -> if there're no rules with checksum field.
// Disabled -> if events monitors are not available.
// Disabled -> if the user disables it globally.
// TODO: Disabled -> if there were n rules with checksums, but the user delete them.
func (e *EventsStore) GetComputeChecksums() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.checksumsEnabled
}

func monitorEventsCache() {
	for {
		<-eventsCacheTicker.C
		EventsCache.DeleteOldItems()
	}
}
