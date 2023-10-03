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
	pidTTL = 3600 // seconds
	// the 2nd cache of items is by path.
	//
	pathTTL = 3600 * 24 // 1 day
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
	sync.RWMutex
	Proc     *Process
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
	eventByPID map[int]*ExecEventItem
	// a path will have multiple pids, hashes will be computed only once by path
	eventByPath      map[string]*ExecEventItem
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
		mu:          &sync.RWMutex{},
		checksums:   make(map[string]uint, 500),
		eventByPID:  make(map[int]*ExecEventItem, 500),
		eventByPath: make(map[string]*ExecEventItem, 500),
	}
}

// Add adds a new process to cache.
// If computing checksums is enabled, new checksums will be computed if needed,
// or reused existing ones otherwise.
func (e *EventsStore) Add(proc *Process) {
	log.Debug("[cache] EventsStore.Add() %d, %s", proc.ID, proc.Path)
	// add the item to cache ASAP
	// then calculate the checksums if needed.
	e.UpdateItem(proc)
	if e.GetComputeChecksums() {
		e.ComputeChecksums(proc)
		e.UpdateItem(proc)
	}
}

// UpdateItem updates a cache item
func (e *EventsStore) UpdateItem(proc *Process) {
	log.Debug("[cache] updateItem() adding to events store (total: %d), pid: %d, paths: %s", e.Len(), proc.ID, proc.Path)
	if proc.Path == "" {
		return
	}
	e.mu.Lock()
	ev := &ExecEventItem{
		Proc:     proc,
		LastSeen: time.Now().UnixNano(),
	}
	e.eventByPID[proc.ID] = ev
	e.eventByPath[proc.Path] = ev
	e.mu.Unlock()
}

// IsInStore checks if a PID is in the store.
// If the PID is in cache, we may need to update it if the PID
// is reusing the PID of the parent.
func (e *EventsStore) IsInStore(key int, proc *Process) (item *ExecEventItem, needsUpdate bool, found bool) {
	item, found = e.IsInStoreByPID(key)
	if !found {
		return
	}
	log.Debug("[cache] Event found by PID: %d, %s", key, item.Proc.Path)

	// check if this PID has replaced the PPID:
	// systemd, pid:1234 -> curl, pid:1234 -> curl (i.e.: pid 1234) opens x.x.x.x:443
	// Without this, we would display for example "systemd is connecting to x.x.x.x:443",
	// instead of "curl is connecting to ..."
	// The previous pid+path will still exist as parent of the new child, in proc.Parent
	if proc != nil && proc.Path != "" && item.Proc.Path != proc.Path {
		log.Debug("[event inCache, replacement] new: %d, %s -> inCache: %d -> %s", proc.ID, proc.Path, item.Proc.ID, item.Proc.Path)
		//e.UpdateItem(proc)
		needsUpdate = true
	}

	return
}

// IsInStoreByPID checks if a pid exists in cache.
func (e *EventsStore) IsInStoreByPID(key int) (item *ExecEventItem, found bool) {
	e.mu.RLock()
	item, found = e.eventByPID[key]
	e.mu.RUnlock()
	return
}

// IsInStoreByPath checks if a process exists in cache by path.
func (e *EventsStore) IsInStoreByPath(path string) (item *ExecEventItem, found bool) {
	if path == "" || path == KernelConnection {
		return
	}
	e.mu.RLock()
	item, found = e.eventByPath[path]
	e.mu.RUnlock()
	if found {
		log.Debug("[cache] event found by path: %s", path)
	}
	return
}

// Delete an item from cache
func (e *EventsStore) Delete(key int) {
	e.mu.Lock()
	delete(e.eventByPID, key)
	e.mu.Unlock()
}

// Len returns the number of items in cache.
func (e *EventsStore) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.eventByPID)
}

// DeleteOldItems deletes items that have exceeded the TTL
func (e *EventsStore) DeleteOldItems() {
	e.mu.Lock()
	defer e.mu.Unlock()

	log.Debug("[cache] deleting old events, total byPID: %d, byPath: %d", len(e.eventByPID), len(e.eventByPath))
	for k, item := range e.eventByPID {
		if item.Proc.IsAlive() == false {
			log.Debug("[cache] deleting old PID: %d -> %s", k, item.Proc.Path)
			delete(e.eventByPID, k)
		}
	}
	for path, item := range e.eventByPath {
		if item.Proc.IsAlive() == false {
			log.Debug("[cache] deleting old path: %d -> %s", item.Proc.ID, item.Proc.Path)
			delete(e.eventByPath, path)
		}
	}
}

// -------------------------------------------------------------------------
// TODO: Move to its own package.
// A hashing service than runs in background, and accepts paths to hash
// and returns the hashes for different algorithms (configurables)

// ComputeChecksums decides if we need to compute the checksum of a process or not.
// We don't recalculate hashes during the life of the process.
func (e *EventsStore) ComputeChecksums(proc *Process) {
	if !e.checksumsEnabled {
		return
	}
	log.Debug("[cache] reuseChecksums %d, %s", proc.ID, proc.Path)

	// XXX: why double check if the PID is in cache?
	// reuseChecksums is called from Add(), and before calling Add() we check if
	// the PID is in cache.
	// The problem is that we don't intercept some events (fork, clone*, dup*),
	// and because of this sometimes we don't receive the event of the parent.
	item, _, found := e.IsInStore(proc.ID, proc)
	if !found {
		log.Debug("cache.reuseChecksums() %d not inCache, %s", proc.ID, proc.Path)

		// if parent path and current path are equal, and the parent is alive, see if we have the hash of the parent path
		if !proc.IsChild() {
			proc.ComputeChecksums(e.checksums)
			log.Debug("[cache] reuseChecksums() pid not in cache, not child of parent: %d, %s - %d - %v", proc.ID, proc.Path, proc.Starttime, proc.Checksums)
			return
		}

		// parent path is nil or paths differ or parent is not alive
		// compute new checksums
		log.Debug("[cache] reuseChecksums() proc is child, proc: %d, %d, %s parent: %d, %d, %s", proc.Starttime, proc.ID, proc.Path, proc.Parent.Starttime, proc.Parent.ID, proc.Parent.Path)
		pit, found := e.IsInStoreByPath(proc.Parent.Path)
		if !found {
			//log.Info("cache.reuseChecksums() cache.add() pid not found byPath: %d, %s, parent: %d, %s", proc.ID, proc.Path, proc.Parent.ID, proc.Parent.Path)
			proc.ComputeChecksums(e.checksums)
			return
		}

		// if the parent path is in cache reuse the checksums
		log.Debug("[cache] reuseChecksums() inCache, found by parent path: %d:%s, parent alive: %v, %d:%s", pit.Proc.ID, pit.Proc.Path, proc.Parent.IsAlive(), proc.Parent.ID, proc.Parent.Path)
		if len(pit.Proc.Checksums) == 0 {
			proc.ComputeChecksums(e.checksums)
			return
		}
		log.Debug("[cache] reuseCheckums() reusing checksums: %v", pit.Proc.Checksums)
		proc.Checksums = pit.Proc.Checksums
		return
	}

	// pid found in cache
	// we should check other parameters to see if the pid is really the same process
	// proc/<pid>/maps
	item.Proc.RLock()
	checksumsNum := len(item.Proc.Checksums)
	item.Proc.RUnlock()
	if checksumsNum > 0 && (item.Proc.IsAlive() && item.Proc.Path == proc.Path) {
		log.Debug("[cache] reuseChecksums() cached PID alive, already hashed: %v, %s new: %s", item.Proc.Checksums, item.Proc.Path, proc.Path)
		proc.Checksums = item.Proc.Checksums
		return
	}
	log.Debug("[cache] reuseChecksums() PID found inCache, computing hashes: %s new: %s - hashes: |%v<>%v|", item.Proc.Path, proc.Path, item.Proc.Checksums, proc.Checksums)

	proc.ComputeChecksums(e.checksums)
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

	e.checksumsEnabled = compute
	if !compute {
		for _, item := range e.eventByPID {
			// XXX: reset saved checksums? or keep them in cache?
			item.Proc.Checksums = make(map[string]string)
		}
		return
	}
	for _, item := range e.eventByPID {
		if len(item.Proc.Checksums) == 0 {
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
