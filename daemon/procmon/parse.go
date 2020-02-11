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

type Pid struct {
	FdPath string
	Descriptors []string
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
	pidsCache = make(map[int]*Pid)
	pidsDescriptorsCache = make(map[int][]string)
	maxCachedPids = 24
)

func cleanUpCaches() {
	if len(inodesCache) > maxCachedInodes {
		for k, _ := range inodesCache {
			delete(inodesCache, k)
		}
	}
	if len(pidsCache) > maxCachedPids {
		for k, _ := range pidsCache {
			delete(pidsCache, k)
		}
	}
}

func GetPidByInodeFromCache(inodeKey string) int {
	if _, found := inodesCache[inodeKey]; found == true {
		// sometimes the process may have dissapeared at this point
		if _, err := os.Lstat(fmt.Sprint("/proc/", inodesCache[inodeKey].Pid, "/exe")); err == nil {
			return inodesCache[inodeKey].Pid
		}
		delete(pidsCache, inodesCache[inodeKey].Pid)
		delete(inodesCache, inodeKey)
	}

	return -1
}

func getPidDescriptorsFromCache(pid int, fdPath string, expect string, descriptors []string) int {
	for fdIdx:=0; fdIdx < len(descriptors); fdIdx++ {
		descLink := fmt.Sprint(fdPath, descriptors[fdIdx])
		if link, err := os.Readlink(descLink); err == nil && link == expect {
			return fdIdx
		}
	}

	return -1
}

func getPidFromCache(inode int, inodeKey string, expect string) int {
	// loop over the processes that have generated connections
	for pid, Pid := range pidsCache {
		if idxDesc := getPidDescriptorsFromCache(pid, Pid.FdPath, expect, Pid.Descriptors); idxDesc != -1 {
			return pid
		}

		if descriptors := lookupPidDescriptors(Pid.FdPath); descriptors != nil {
			pidsCache[pid].Descriptors = descriptors

			if idxDesc := getPidDescriptorsFromCache(pid, Pid.FdPath, expect, descriptors); idxDesc != -1 {
				return pid
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
		return cachedPid
	}

	forEachProcess(func(pid int, path string, args []string) bool {
		fdPath := fmt.Sprint("/proc/", pid, "/fd/")
		fd_list := lookupPidDescriptors(fdPath)
		if fd_list == nil {
			return false
		}

		for idx:=0; idx < len(fd_list)-1; idx++ {
			descLink := fmt.Sprint(fdPath, fd_list[idx])
			// resolve the symlink and compare to what we expect
			if link, err := os.Readlink(descLink); err == nil && link == expect {
				found = pid
				inodesCache[inodeKey] = &Inode{ FdPath: descLink, Pid: pid }
				pidsCache[pid] = &Pid{ FdPath: fdPath, Descriptors: fd_list }
				return true
			}
		}
		// keep looping
		return false
	})
	log.Debug("new pid lookup took", time.Since(start))

	return found
}

// ~150us
func lookupPidDescriptors (fdPath string) []string{
	if f, err := os.Open(fdPath); err == nil {
		fd_list, err := f.Readdir(-1)
		f.Close()
		if err != nil {
			return nil
		}
		sort.Slice(fd_list, func(i, j int) bool {
			return fd_list[i].ModTime().After(fd_list[j].ModTime())
		})

		s  := make([]string, len(fd_list))
		for n, f := range fd_list {
			s[n] = f.Name()
		}

		return s
	}

	return nil
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
