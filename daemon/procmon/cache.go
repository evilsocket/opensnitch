package procmon

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
)

var (
	cLock       = sync.RWMutex{}
	cacheTicker = time.NewTicker(2 * time.Minute)
)

// Inode represents an item of the InodesCache.
// the key is formed as follow:
// inode+srcip+srcport+dstip+dstport
type Inode struct {
	Pid      int
	FdPath   string
	LastSeen int64
}

// ProcEntry represents an item of the pidsCache
type ProcEntry struct {
	Pid         int
	FdPath      string
	Descriptors []string
	LastSeen    int64
}

var (
	// cache of inodes, which help to not iterate over all the pidsCache and
	// descriptors of /proc/<pid>/fd/
	// 15-50us vs 50-80ms
	// we hit this cache when:
	// - we've blocked a connection and the process retries it several times until it gives up,
	// - or when a process timeouts connecting to an IP/domain and it retries it again,
	// - or when a process resolves a domain and then connects to the IP.
	inodesCache = make(map[string]*Inode)
	maxTTL      = 5 // maximum 5 minutes of inactivity in cache. Really rare, usually they lasts less than a minute.

	// 2nd cache of already known running pids, which also saves time by
	// iterating only over a few pids' descriptors, (30us-20ms vs. 50-80ms)
	// since it's more likely that most of the connections will be made by the
	// same (running) processes.
	// The cache is ordered by time, placing in the first places those PIDs with
	// active connections.
	pidsCache            []*ProcEntry
	pidsDescriptorsCache = make(map[int][]string)
)

func addProcEntry(fdPath string, fdList []string, pid int) {
	for n := range pidsCache {
		if pidsCache[n].Pid == pid {
			pidsCache[n].Descriptors = fdList
			pidsCache[n].LastSeen = time.Now().UnixNano()
			return
		}
	}
	procEntry := &ProcEntry{
		Pid:         pid,
		FdPath:      fdPath,
		Descriptors: fdList,
		LastSeen:    time.Now().UnixNano(),
	}
	pidsCache = append([]*ProcEntry{procEntry}, pidsCache...)
}

func addInodeEntry(key, descLink string, pid int) {
	cLock.Lock()
	defer cLock.Unlock()

	inodesCache[key] = &Inode{
		FdPath:   descLink,
		Pid:      pid,
		LastSeen: time.Now().UnixNano(),
	}
}

func sortProcEntries() {
	sort.Slice(pidsCache, func(i, j int) bool {
		t := pidsCache[i].LastSeen
		u := pidsCache[j].LastSeen
		return t > u || t == u
	})
}

func deleteProcEntry(pid int) {
	for n, procEntry := range pidsCache {
		if procEntry.Pid == pid {
			pidsCache = append(pidsCache[:n], pidsCache[n+1:]...)
			deleteInodeEntry(pid)
			break
		}
	}
}

func deleteInodeEntry(pid int) {
	cLock.Lock()
	defer cLock.Unlock()

	for k, inodeEntry := range inodesCache {
		if inodeEntry.Pid == pid {
			delete(inodesCache, k)
		}
	}
}

func CacheCleanerTask() {
	for {
		select {
		case <-cacheTicker.C:
			cleanupInodes()
		}
	}
}

func cleanupInodes() {
	cLock.Lock()
	defer cLock.Unlock()

	now := time.Now()
	for k := range inodesCache {
		lastSeen := now.Sub(
			time.Unix(0, inodesCache[k].LastSeen),
		)
		if core.Exists(inodesCache[k].FdPath) == false || int(lastSeen.Minutes()) > maxTTL {
			delete(inodesCache, k)
		}
	}
}

func getPidByInodeFromCache(inodeKey string) int {
	cLock.Lock()
	defer cLock.Unlock()

	if _, found := inodesCache[inodeKey]; found == true {
		// sometimes the process may have disappeared at this point
		if _, err := os.Lstat(fmt.Sprint("/proc/", inodesCache[inodeKey].Pid, "/exe")); err == nil {
			inodesCache[inodeKey].LastSeen = time.Now().UnixNano()
			return inodesCache[inodeKey].Pid
		}
		deleteProcEntry(inodesCache[inodeKey].Pid)
	}

	return -1
}

func getPidDescriptorsFromCache(fdPath, inodeKey, expect string, descriptors *[]string, pid int) (int, *[]string) {
	for fdIdx := 0; fdIdx < len(*descriptors); fdIdx++ {
		descLink := fmt.Sprint(fdPath, (*descriptors)[fdIdx])
		if link, err := os.Readlink(descLink); err == nil && link == expect {
			if fdIdx > 0 {
				// reordering helps to reduce look up times by a factor of 10.
				fd := (*descriptors)[fdIdx]
				*descriptors = append((*descriptors)[:fdIdx], (*descriptors)[fdIdx+1:]...)
				*descriptors = append([]string{fd}, *descriptors...)
			}
			if _, found := inodesCache[inodeKey]; !found {
				addInodeEntry(inodeKey, descLink, pid)
			}
			return fdIdx, descriptors
		}
	}

	return -1, descriptors
}

func getPidFromCache(inode int, inodeKey string, expect string) (int, int) {
	// loop over the processes that have generated connections
	for n := 0; n < len(pidsCache); n++ {
		if idxDesc, newFdList := getPidDescriptorsFromCache(pidsCache[n].FdPath, inodeKey, expect, &pidsCache[n].Descriptors, pidsCache[n].Pid); idxDesc != -1 {
			pidsCache[n].LastSeen = time.Now().UnixNano()
			pidsCache[n].Descriptors = *newFdList
			return pidsCache[n].Pid, n
		}
	}
	// inode not found in cache, we need to refresh the list of descriptors
	// to see if any known PID has opened a new socket
	for n := 0; n < len(pidsCache); n++ {
		descriptors := lookupPidDescriptors(pidsCache[n].FdPath, pidsCache[n].Pid)
		if descriptors == nil {
			deleteProcEntry(pidsCache[n].Pid)
			continue
		}

		pidsCache[n].Descriptors = descriptors
		if idxDesc, newFdList := getPidDescriptorsFromCache(pidsCache[n].FdPath, inodeKey, expect, &descriptors, pidsCache[n].Pid); idxDesc != -1 {
			pidsCache[n].LastSeen = time.Now().UnixNano()
			pidsCache[n].Descriptors = *newFdList
			return pidsCache[n].Pid, n
		}
	}

	return -1, -1
}
