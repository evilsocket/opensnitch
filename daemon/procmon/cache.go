package procmon

import (
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
)

// InodeItem represents an item of the InodesCache.
type InodeItem struct {
	FdPath   string
	Pid      int
	LastSeen int64
	sync.RWMutex
}

// ProcItem represents an item of the pidsCache
type ProcItem struct {
	FdPath      string
	Descriptors []string
	Pid         int
	LastSeen    int64
	sync.RWMutex
}

// CacheProcs holds the cache of processes that have established connections.
type CacheProcs struct {
	items []*ProcItem
	sync.RWMutex
}

// CacheInodes holds the cache of Inodes.
// The key is formed as follow:
// inode+srcip+srcport+dstip+dstport
type CacheInodes struct {
	items map[string]*InodeItem
	sync.RWMutex
}

var (
	// cache of inodes, which help to not iterate over all the pidsCache and
	// descriptors of /proc/<pid>/fd/
	// 15-50us vs 50-80ms
	// we hit this cache when:
	// - we've blocked a connection and the process retries it several times until it gives up,
	// - or when a process timeouts connecting to an IP/domain and it retries it again,
	// - or when a process resolves a domain and then connects to the IP.
	inodesCache = NewCacheOfInodes()
	maxTTL      = 3 // maximum 3 minutes of inactivity in cache. Really rare, usually they lasts less than a minute.

	// 2nd cache of already known running pids, which also saves time by
	// iterating only over a few pids' descriptors, (30us-20ms vs. 50-80ms)
	// since it's more likely that most of the connections will be made by the
	// same (running) processes.
	// The cache is ordered by time, placing in the first places those PIDs with
	// active connections.
	pidsCache            CacheProcs
	pidsDescriptorsCache = make(map[int][]string)

	cacheTicker = time.NewTicker(2 * time.Minute)
)

// CacheCleanerTask checks periodically if the inodes in the cache must be removed.
func CacheCleanerTask() {
	for {
		select {
		case <-cacheTicker.C:
			inodesCache.cleanup()
		}
	}
}

// NewCacheOfInodes returns a new cache for inodes.
func NewCacheOfInodes() *CacheInodes {
	return &CacheInodes{
		items: make(map[string]*InodeItem),
	}
}

//******************************************************************************
// items of the caches.

func (i *InodeItem) updateTime() {
	i.Lock()
	i.LastSeen = time.Now().UnixNano()
	i.Unlock()
}

func (i *InodeItem) getTime() int64 {
	i.RLock()
	defer i.RUnlock()
	return i.LastSeen
}

func (p *ProcItem) updateTime() {
	p.Lock()
	p.LastSeen = time.Now().UnixNano()
	p.Unlock()
}

func (p *ProcItem) updateDescriptors(descriptors []string) {
	p.Lock()
	p.Descriptors = descriptors
	p.Unlock()
}

//******************************************************************************
// cache of processes

func (c *CacheProcs) add(fdPath string, fdList []string, pid int) {
	c.Lock()
	defer c.Unlock()
	for n := range c.items {
		item := c.items[n]
		if item == nil {
			continue
		}
		if item.Pid == pid {
			item.updateTime()
			return
		}
	}

	procItem := &ProcItem{
		Pid:         pid,
		FdPath:      fdPath,
		Descriptors: fdList,
		LastSeen:    time.Now().UnixNano(),
	}

	c.setItems([]*ProcItem{procItem}, c.items)
}

func (c *CacheProcs) sort(pid int) {
	item := c.getItem(0)
	if item != nil && item.Pid == pid {
		return
	}
	c.RLock()
	defer c.RUnlock()

	sort.Slice(c.items, func(i, j int) bool {
		t := c.items[i].LastSeen
		u := c.items[j].LastSeen
		return t > u || t == u
	})
}

func (c *CacheProcs) delete(pid int) {
	c.Lock()
	defer c.Unlock()

	for n, procItem := range c.items {
		if procItem.Pid == pid {
			c.deleteItem(n)
			inodesCache.delete(pid)
			break
		}
	}
}

func (c *CacheProcs) deleteItem(pos int) {
	nItems := len(c.items)
	if pos < nItems {
		c.setItems(c.items[:pos], c.items[pos+1:])
	}
}

func (c *CacheProcs) setItems(newItems []*ProcItem, oldItems []*ProcItem) {
	c.items = append(newItems, oldItems...)
}

func (c *CacheProcs) getItem(index int) *ProcItem {
	c.RLock()
	defer c.RUnlock()

	if index >= len(c.items) {
		return nil
	}

	return c.items[index]
}

func (c *CacheProcs) getItems() []*ProcItem {
	return c.items
}

func (c *CacheProcs) countItems() int {
	c.RLock()
	defer c.RUnlock()

	return len(c.items)
}

// loop over the processes that have generated connections
func (c *CacheProcs) getPid(inode int, inodeKey string, expect string) (int, int) {
	c.Lock()
	defer c.Unlock()

	for n, procItem := range c.items {
		if procItem == nil {
			continue
		}

		if idxDesc, _ := getPidDescriptorsFromCache(procItem.FdPath, inodeKey, expect, &procItem.Descriptors, procItem.Pid); idxDesc != -1 {
			procItem.updateTime()
			return procItem.Pid, n
		}

		descriptors := lookupPidDescriptors(procItem.FdPath, procItem.Pid)
		if descriptors == nil {
			c.deleteItem(n)
			continue
		}

		procItem.updateDescriptors(descriptors)
		if idxDesc, _ := getPidDescriptorsFromCache(procItem.FdPath, inodeKey, expect, &descriptors, procItem.Pid); idxDesc != -1 {
			procItem.updateTime()
			return procItem.Pid, n
		}
	}

	return -1, -1
}

//******************************************************************************
// cache of inodes

func (i *CacheInodes) add(key, descLink string, pid int) {
	i.Lock()
	defer i.Unlock()

	if descLink == "" {
		descLink = core.ConcatStrings("/proc/", strconv.Itoa(pid), "/exe")
	}
	i.items[key] = &InodeItem{
		FdPath:   descLink,
		Pid:      pid,
		LastSeen: time.Now().UnixNano(),
	}
}

func (i *CacheInodes) delete(pid int) {
	i.Lock()
	defer i.Unlock()

	for k, inodeItem := range i.items {
		if inodeItem.Pid == pid {
			delete(i.items, k)
		}
	}
}

func (i *CacheInodes) getPid(inodeKey string) int {
	if item, ok := i.isInCache(inodeKey); ok {
		// sometimes the process may have disappeared at this point
		if _, err := os.Lstat(item.FdPath); err == nil {
			item.updateTime()
			return item.Pid
		}
		pidsCache.delete(item.Pid)
		i.delItem(inodeKey)
	}

	return -1
}

func (i *CacheInodes) delItem(inodeKey string) {
	i.Lock()
	defer i.Unlock()
	delete(i.items, inodeKey)
}

func (i *CacheInodes) getItem(inodeKey string) *InodeItem {
	i.RLock()
	defer i.RUnlock()

	return i.items[inodeKey]
}

func (i *CacheInodes) getItems() map[string]*InodeItem {
	i.RLock()
	defer i.RUnlock()

	return i.items
}

func (i *CacheInodes) isInCache(inodeKey string) (*InodeItem, bool) {
	i.RLock()
	defer i.RUnlock()

	if item, found := i.items[inodeKey]; found {
		return item, true
	}
	return nil, false
}

func (i *CacheInodes) cleanup() {
	now := time.Now()
	i.Lock()
	defer i.Unlock()
	for k := range i.items {
		if i.items[k] == nil {
			continue
		}
		lastSeen := now.Sub(
			time.Unix(0, i.items[k].getTime()),
		)
		if core.Exists(i.items[k].FdPath) == false || int(lastSeen.Minutes()) > maxTTL {
			delete(i.items, k)
		}
	}
}

func getPidDescriptorsFromCache(fdPath, inodeKey, expect string, descriptors *[]string, pid int) (int, *[]string) {
	for fdIdx := 0; fdIdx < len(*descriptors); fdIdx++ {
		descLink := core.ConcatStrings(fdPath, (*descriptors)[fdIdx])
		if link, err := os.Readlink(descLink); err == nil && link == expect {
			if fdIdx > 0 {
				// reordering helps to reduce look up times by a factor of 10.
				fd := (*descriptors)[fdIdx]
				*descriptors = append((*descriptors)[:fdIdx], (*descriptors)[fdIdx+1:]...)
				*descriptors = append([]string{fd}, *descriptors...)
			}
			if _, ok := inodesCache.isInCache(inodeKey); ok {
				inodesCache.add(inodeKey, descLink, pid)
			}
			return fdIdx, descriptors
		}
	}

	return -1, descriptors
}
