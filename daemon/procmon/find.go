package procmon

import (
	"os"
	"sort"
	"strconv"

	"github.com/evilsocket/opensnitch/daemon/core"
)

func sortPidsByTime(fdList []os.FileInfo) []os.FileInfo {
	sort.Slice(fdList, func(i, j int) bool {
		t := fdList[i].ModTime().UnixNano()
		u := fdList[j].ModTime().UnixNano()
		return t > u
	})
	return fdList
}

// inodeFound searches for the given inode in /proc/<pid>/fd/ or
// /proc/<pid>/task/<tid>/fd/ and gets the symbolink link it points to,
// in order to compare it against the given inode.
//
// If the inode is found, the cache is updated ans sorted.
func inodeFound(pidsPath, expect, inodeKey string, inode, pid int) bool {
	fdPath := core.ConcatStrings(pidsPath, strconv.Itoa(pid), "/fd/")
	fdList := lookupPidDescriptors(fdPath, pid)
	if fdList == nil {
		return false
	}

	for idx := 0; idx < len(fdList); idx++ {
		descLink := core.ConcatStrings(fdPath, fdList[idx])
		if link, err := os.Readlink(descLink); err == nil && link == expect {
			inodesCache.add(inodeKey, descLink, pid)
			pidsCache.add(fdPath, fdList, pid)
			return true
		}
	}

	return false
}

// lookupPidInProc searches for an inode in /proc.
// First it gets the running PIDs and obtains the opened sockets.
// TODO: If the inode is not found, search again in the task/threads
// of every PID (costly).
func lookupPidInProc(pidsPath, expect, inodeKey string, inode int) int {
	pidList := getProcPids(pidsPath)
	for _, pid := range pidList {
		if inodeFound(pidsPath, expect, inodeKey, inode, pid) {
			return pid
		}
	}
	return -1
}

// lookupPidDescriptors returns the list of descriptors inside
// /proc/<pid>/fd/
// TODO: search in /proc/<pid>/task/<tid>/fd/ .
func lookupPidDescriptors(fdPath string, pid int) []string {
	f, err := os.Open(fdPath)
	if err != nil {
		return nil
	}
	// This is where most of the time is wasted when looking for PIDs.
	// long running processes like firefox/chrome tend to have a lot of descriptor
	// references that points to non existent files on disk, but that remains in
	// memory (those with " (deleted)").
	// This causes to have to iterate over 300 to 700 items, that are not sockets.
	fdList, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return nil
	}
	fdList = sortPidsByTime(fdList)

	s := make([]string, len(fdList))
	for n, f := range fdList {
		s[n] = f.Name()
	}

	return s
}

// getProcPids returns the list of running PIDs, /proc or /proc/<pid>/task/ .
func getProcPids(pidsPath string) (pidList []int) {
	f, err := os.Open(pidsPath)
	if err != nil {
		return pidList
	}
	ls, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return pidList
	}
	ls = sortPidsByTime(ls)

	for _, f := range ls {
		if f.IsDir() == false {
			continue
		}
		if pid, err := strconv.Atoi(f.Name()); err == nil {
			pidList = append(pidList, []int{pid}...)
		}
	}

	return pidList
}
