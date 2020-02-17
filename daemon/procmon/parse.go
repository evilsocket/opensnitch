package procmon

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
	"sort"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/core"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
)

type Inode struct {
	Pid	 int
	FdPath  string
}

type ProcEntry struct {
	Pid int
	FdPath string
	Descriptors []string
	Time time.Time
}

var (
	// cache of inodes, which help to not iterate over all the pidsCache and
	// descriptors of /proc/<pid>/fd/
	// 20-500us vs 50-80ms
	inodesCache = make(map[string]*Inode)
	maxCachedInodes = 24
	// 2nd cache of already known running pids, which also saves time by
	// iterating only over a few pids' descriptors, (30us-2ms vs. 50-80ms)
	// since it's more likely that most of the connections will be made by the
	// same (running) processes
	pidsCache []*ProcEntry
	pidsDescriptorsCache = make(map[int][]string)
	maxCachedPids = 24

	ourPid = os.Getpid()
)

func addProcEntry(fdPath string, fd_list []string, pid int) {
	for n, _ := range pidsCache {
		if pidsCache[n].Pid == pid {
			pidsCache[n].Time = time.Now()
			return
		}
	}
	pidsCache = append(pidsCache, &ProcEntry{ Pid: pid, FdPath: fdPath, Descriptors: fd_list, Time: time.Now() })
}

func sortProcEntries() {
	sort.Slice(pidsCache, func(i, j int) bool {
		t := pidsCache[i].Time.UnixNano()
		u := pidsCache[j].Time.UnixNano()
		return u == t || t > u
	})
}

func deleteProcEntry(pid int) {
	for n, procEntry := range pidsCache {
		if procEntry.Pid == pid {
			pidsCache = append(pidsCache[:n], pidsCache[n+1:]...)
			break
		}
	}
}

func cleanUpCaches() {
	if len(inodesCache) > maxCachedInodes {
		for k, _ := range inodesCache {
			delete(inodesCache, k)
		}
	}
	if len(pidsCache) > maxCachedPids {
		pidsCache = nil
	}
}

func GetPidByInodeFromCache(inodeKey string) int {
	if _, found := inodesCache[inodeKey]; found == true {
		// sometimes the process may have dissapeared at this point
		if _, err := os.Lstat(fmt.Sprint("/proc/", inodesCache[inodeKey].Pid, "/exe")); err == nil {
			return inodesCache[inodeKey].Pid
		}
		deleteProcEntry(inodesCache[inodeKey].Pid)
		delete(inodesCache, inodeKey)
	}

	return -1
}

func getPidDescriptorsFromCache(pid int, fdPath string, expect string, descriptors []string) int {
	for fdIdx:=0; fdIdx < len(descriptors); fdIdx++ {
		descLink := fmt.Sprint(fdPath, descriptors[fdIdx])
		if link, err := os.Readlink(descLink); err == nil && link == expect {
			if err != nil {
				deleteProcEntry(pid)
			}
			return fdIdx
		}
	}

	return -1
}

func getPidFromCache(inode int, inodeKey string, expect string) int {
	// loop over the processes that have generated connections
	for n, procEntry := range pidsCache {
		if idxDesc := getPidDescriptorsFromCache(procEntry.Pid, procEntry.FdPath, expect, procEntry.Descriptors); idxDesc != -1 {
			pidsCache[n].Time = time.Now()
			return procEntry.Pid
		}

		if descriptors := lookupPidDescriptors(procEntry.FdPath); descriptors != nil {
			pidsCache[n].Descriptors = descriptors

			if idxDesc := getPidDescriptorsFromCache(procEntry.Pid, procEntry.FdPath, expect, descriptors); idxDesc != -1 {
				pidsCache[n].Time = time.Now()
				return procEntry.Pid
			}
		}
	}

	return -1
}


func GetPIDFromINode(inode int, inodeKey string) int {
	found := -1
	if inode <= 0 {
		return found
	}
	start := time.Now()
	cleanUpCaches()

	expect := fmt.Sprintf("socket:[%d]", inode)
	if cachedPidInode := GetPidByInodeFromCache(inodeKey); cachedPidInode != -1 {
		log.Debug("Inode found in cache", time.Since(start), inodesCache[inodeKey], inode, inodeKey)
		return cachedPidInode
	}

	cachedPid := getPidFromCache(inode, inodeKey, expect)
	if cachedPid != -1 {
		log.Debug("Socket found in known pids %v, pid: %d, inode: %d, pids in cache: %d", time.Since(start), cachedPid, inode, len(pidsCache))
		sortProcEntries()
		return cachedPid
	}

	if IsWatcherAvailable() {
		forEachProcess(func(pid int, path string, args []string) bool {
			if inodeFound("/proc/", expect, inodeKey, inode, pid) {
				found = pid
				return true
			}
			// keep looping
			return false
		})
	} else {
		found = lookupPidInProc("/proc/", expect, inodeKey, inode)
	}
	log.Debug("new pid lookup took", found, time.Since(start))

	return found
}

func parseCmdLine(proc *Process) {
	if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", proc.ID)); err == nil {
		for i, b := range data {
			if b == 0x00 {
				data[i] = byte(' ')
			}
		}

		args := strings.Split(string(data), " ")
		for _, arg := range args {
			arg = core.Trim(arg)
			if arg != "" {
				proc.Args = append(proc.Args, arg)
			}
		}
	}
}

func parseEnv(proc *Process) {
	if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/environ", proc.ID)); err == nil {
		for _, s := range strings.Split(string(data), "\x00") {
			parts := strings.SplitN(core.Trim(s), "=", 2)
			if parts != nil && len(parts) == 2 {
				key := core.Trim(parts[0])
				val := core.Trim(parts[1])
				proc.Env[key] = val
			}
		}
	}
}

func FindProcess(pid int, interceptUnknown bool) *Process {
	if interceptUnknown && pid < 0 {
		return NewProcess(0, "")
	}
	linkName := fmt.Sprint("/proc/", pid, "/exe")
	if _, err := os.Lstat(linkName); err != nil {
		return nil
	}

	if link, err := os.Readlink(linkName); err == nil {
		proc := NewProcess(pid, strings.Split(link, " ")[0])

		parseCmdLine(proc)
		parseEnv(proc)

		return proc
	}
	return nil
}
