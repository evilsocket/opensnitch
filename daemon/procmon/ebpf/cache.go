package ebpf

import (
	"sync"
	"time"
)

type ebpfCacheItem struct {
	Key      []byte
	LastSeen int64
	UID      int
	Pid      int
	Hits     uint
}

type ebpfCacheType struct {
	Items map[string]*ebpfCacheItem
	sync.RWMutex
}

var (
	maxTTL          = 20 // Seconds
	maxCacheItems   = 5000
	ebpfCache       *ebpfCacheType
	ebpfCacheTicker *time.Ticker
)

// NewEbpfCacheItem creates a new cache item.
func NewEbpfCacheItem(key []byte, pid, uid int) *ebpfCacheItem {
	return &ebpfCacheItem{
		Key:      key,
		Hits:     1,
		Pid:      pid,
		UID:      uid,
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
		Items: make(map[string]*ebpfCacheItem, 0),
	}
}

func (e *ebpfCacheType) addNewItem(key string, itemKey []byte, pid, uid int) {
	e.Lock()
	defer e.Unlock()

	e.Items[key] = NewEbpfCacheItem(itemKey, pid, uid)
}

func (e *ebpfCacheType) isInCache(key string) (item *ebpfCacheItem, found bool) {
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

func (e *ebpfCacheType) update(key string, item *ebpfCacheItem) {
	item.Hits++
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
		if length > maxCacheItems || !item.isValid() {
			delete(e.Items, k)
		}
	}
}

func (e *ebpfCacheType) clear() {
	if e == nil {
		return
	}
	for k := range e.Items {
		delete(e.Items, k)
	}

	if ebpfCacheTicker != nil {
		ebpfCacheTicker.Stop()
	}
}
