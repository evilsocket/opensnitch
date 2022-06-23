package ebpf

import (
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/procmon"
)

// NewExecEvent constructs a new execEvent from the arguments.
func NewExecEvent(pid, ppid, uid uint64, path string, comm [16]byte) *execEvent {
	ev := &execEvent{
		Type: EV_TYPE_EXEC,
		PID:  pid,
		PPID: ppid,
		UID:  uid,
		Comm: comm,
	}
	length := 128
	if len(path) < 128 {
		length = len(path)
	}
	copy(ev.Filename[:], path[:length])
	return ev
}

type execEventItem struct {
	Proc     procmon.Process
	Event    execEvent
	LastSeen int64
}

type eventsStore struct {
	execEvents map[uint64]*execEventItem
	sync.RWMutex
}

// NewEventsStore creates a new store of events.
func NewEventsStore() *eventsStore {
	return &eventsStore{
		execEvents: make(map[uint64]*execEventItem),
	}
}

func (e *eventsStore) add(key uint64, event execEvent) {
	e.Lock()
	defer e.Unlock()
	e.execEvents[key] = &execEventItem{
		Event: event,
	}
}

func (e *eventsStore) isInStore(key uint64) (item *execEventItem, found bool) {
	e.RLock()
	defer e.RUnlock()
	item, found = e.execEvents[key]
	return
}

func (e *eventsStore) delete(key uint64) {
	e.Lock()
	defer e.Unlock()
	delete(e.execEvents, key)
}

//-----------------------------------------------------------------------------

type ebpfCacheItem struct {
	Proc     procmon.Process
	Key      []byte
	LastSeen int64
}

type ebpfCacheType struct {
	Items map[interface{}]*ebpfCacheItem
	sync.RWMutex
}

var (
	maxTTL          = 40 // Seconds
	maxCacheItems   = 5000
	ebpfCache       *ebpfCacheType
	ebpfCacheTicker *time.Ticker
)

// NewEbpfCacheItem creates a new cache item.
func NewEbpfCacheItem(key []byte, proc procmon.Process) *ebpfCacheItem {
	return &ebpfCacheItem{
		Key:      key,
		Proc:     proc,
		LastSeen: time.Now().UnixNano(),
	}
}

func (i *ebpfCacheItem) isValid() bool {
	lastSeen := time.Now().Sub(
		time.Unix(0, i.LastSeen),
	)
	return int(lastSeen.Seconds()) < maxTTL
}

// NewEbpfCache creates a new cache store.
func NewEbpfCache() *ebpfCacheType {
	ebpfCacheTicker = time.NewTicker(1 * time.Minute)
	return &ebpfCacheType{
		Items: make(map[interface{}]*ebpfCacheItem, 0),
	}
}

func (e *ebpfCacheType) addNewItem(key interface{}, itemKey []byte, proc procmon.Process) {
	e.Lock()
	e.Items[key] = NewEbpfCacheItem(itemKey, proc)
	e.Unlock()
}

func (e *ebpfCacheType) isInCache(key interface{}) (item *ebpfCacheItem, found bool) {
	leng := e.Len()

	e.Lock()
	item, found = e.Items[key]
	if found {
		if item.isValid() {
			e.update(key, item)
		} else {
			found = false
			delete(e.Items, key)
		}
	}
	e.Unlock()

	if leng > maxCacheItems {
		e.DeleteOldItems()
	}
	return
}

func (e *ebpfCacheType) update(key interface{}, item *ebpfCacheItem) {
	item.LastSeen = time.Now().UnixNano()
	e.Items[key] = item
}

func (e *ebpfCacheType) Len() int {
	e.RLock()
	defer e.RUnlock()
	return len(e.Items)
}

func (e *ebpfCacheType) DeleteOldItems() {
	length := e.Len()

	e.Lock()
	defer e.Unlock()

	for k, item := range e.Items {
		if length > maxCacheItems || (item != nil && !item.isValid()) {
			delete(e.Items, k)
		}
	}
}

func (e *ebpfCacheType) delete(key interface{}) {
	e.Lock()
	defer e.Unlock()

	if key, found := e.Items[key]; found {
		delete(e.Items, key)
	}
}

func (e *ebpfCacheType) clear() {
	if e == nil {
		return
	}
	e.Lock()
	defer e.Unlock()
	for k := range e.Items {
		delete(e.Items, k)
	}

	if ebpfCacheTicker != nil {
		ebpfCacheTicker.Stop()
	}
}
