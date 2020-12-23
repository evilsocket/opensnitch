package procmon

import (
	"fmt"
	"os"
	"sort"
	"time"
)

// Inode represents an item of the InodesCache.
// the key is formed as follow:
// inode+srcip+srcport+dstip+dstport
type Inode struct {
	Pid    int
	FdPath string
}

// ProcEntry represents an item of the pidsCache
type ProcEntry struct {
	Pid         int
	FdPath      string
	Descriptors []string
	Time        time.Time
}

var (
	// cache of inodes, which help to not iterate over all the pidsCache and
	// descriptors of /proc/<pid>/fd/
	// 20-50us vs 50-80ms
	inodesCache     = make(map[string]*Inode)
	maxCachedInodes = 128
	// 2nd cache of already known running pids, which also saves time by
	// iterating only over a few pids' descriptors, (30us-2ms vs. 50-80ms)
	// since it's more likely that most of the connections will be made by the
	// same (running) processes.
	// The cache is ordered by time, placing in the first places those PIDs with
	// active connections.
	pidsCache            []*ProcEntry
	pidsDescriptorsCache = make(map[int][]string)
	maxCachedPids        = 24
)

func addProcEntry(fdPath string, fdList []string, pid int) {
	for n := range pidsCache {
		if pidsCache[n].Pid == pid {
			pidsCache[n].Time = time.Now()
			return
		}
	}
	procEntry := &ProcEntry{
		Pid:         pid,
		FdPath:      fdPath,
		Descriptors: fdList,
		Time:        time.Now(),
	}
	pidsCache = append([]*ProcEntry{procEntry}, pidsCache...)
}

func sortProcEntries() {
	sort.Slice(pidsCache, func(i, j int) bool {
		t := pidsCache[i].Time.UnixNano()
		u := pidsCache[j].Time.UnixNano()
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
	for k, inodeEntry := range inodesCache {
		if inodeEntry.Pid == pid {
			delete(inodesCache, k)
		}
	}
}

func cleanUpCaches() {
	if len(inodesCache) > maxCachedInodes {
		for k := range inodesCache {
			delete(inodesCache, k)
		}
	}
	if len(pidsCache) > maxCachedPids {
		pidsCache = nil
	}
}

func getPidByInodeFromCache(inodeKey string) int {
	if _, found := inodesCache[inodeKey]; found == true {
		// sometimes the process may have disappeared at this point
		if _, err := os.Lstat(fmt.Sprint("/proc/", inodesCache[inodeKey].Pid, "/exe")); err == nil {
			return inodesCache[inodeKey].Pid
		}
		deleteProcEntry(inodesCache[inodeKey].Pid)
	}

	return -1
}

func getPidDescriptorsFromCache(pid int, fdPath string, expect string, descriptors []string) int {
	for fdIdx := 0; fdIdx < len(descriptors); fdIdx++ {
		descLink := fmt.Sprint(fdPath, descriptors[fdIdx])
		if link, err := os.Readlink(descLink); err == nil && link == expect {
			return fdIdx
		}
	}

	return -1
}

func getPidFromCache(inode int, inodeKey string, expect string) (int, int) {
	// loop over the processes that have generated connections
	for n := 0; n < len(pidsCache); n++ {
		procEntry := pidsCache[n]

		if idxDesc := getPidDescriptorsFromCache(procEntry.Pid, procEntry.FdPath, expect, procEntry.Descriptors); idxDesc != -1 {
			pidsCache[n].Time = time.Now()
			return procEntry.Pid, n
		}

		descriptors := lookupPidDescriptors(procEntry.FdPath)
		if descriptors == nil {
			deleteProcEntry(procEntry.Pid)
			continue
		}

		pidsCache[n].Descriptors = descriptors
		if idxDesc := getPidDescriptorsFromCache(procEntry.Pid, procEntry.FdPath, expect, descriptors); idxDesc != -1 {
			pidsCache[n].Time = time.Now()
			return procEntry.Pid, n
		}
	}

	return -1, -1
}
