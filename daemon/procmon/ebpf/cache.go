package ebpf

import (
	"sync"
	"time"
)

type ebpfCacheItem struct {
	Key      []byte
	LastSeen int64
	Pid      int
}

type ebpfCacheType struct {
	Items map[interface{}]*ebpfCacheItem
	mu    *sync.RWMutex
}

var (
	// TODO: allow to configure these options
	maxTTL          = 40 // Seconds
	maxCacheItems   = 50000
	ebpfCache       *ebpfCacheType
	ebpfCacheTicker *time.Ticker
)

// NewEbpfCacheItem creates a new cache item.
func NewEbpfCacheItem(key []byte, pid int) *ebpfCacheItem {
	return &ebpfCacheItem{
		Key:      key,
		Pid:      pid,
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
		Items: make(map[interface{}]*ebpfCacheItem, 500),
		mu:    &sync.RWMutex{},
	}
}

func (e *ebpfCacheType) addNewItem(key interface{}, itemKey []byte, pid int) {
	e.mu.Lock()
	e.Items[key] = NewEbpfCacheItem(itemKey, pid)
	e.mu.Unlock()
}

func (e *ebpfCacheType) isInCache(key interface{}) (item *ebpfCacheItem, found bool) {
	leng := e.Len()

	e.mu.Lock()
	item, found = e.Items[key]
	if found {
		if item.isValid() {
			e.update(key, item)
		} else {
			found = false
			delete(e.Items, key)
		}
	}
	e.mu.Unlock()

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
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.Items)
}

func (e *ebpfCacheType) DeleteOldItems() {
	length := e.Len()

	e.mu.Lock()
	defer e.mu.Unlock()

	for k, item := range e.Items {
		if length > maxCacheItems || (item != nil && !item.isValid()) {
			delete(e.Items, k)
		}
	}
}

func (e *ebpfCacheType) delete(key interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if key, found := e.Items[key]; found {
		delete(e.Items, key)
	}
}

func (e *ebpfCacheType) clear() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.Items {
		delete(e.Items, k)
	}

	if ebpfCacheTicker != nil {
		ebpfCacheTicker.Stop()
	}
}
