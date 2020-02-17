package procmon

import (
	"fmt"
	"os"
	"sort"
	"strconv"
)

// inodeFound searches for the given inode in /proc/<pid>/fd/ or
// /proc/<pid>/task/<tid>/fd/ and gets the symbolink link it points to,
// in order to compare it against the given inode.
func inodeFound(pidsPath, expect, inodeKey string, inode, pid int) bool {
	fdPath := fmt.Sprint(pidsPath, pid, "/fd/")
	fd_list := lookupPidDescriptors(fdPath)
	if fd_list == nil {
		return false
	}

	for idx:=0; idx < len(fd_list)-1; idx++ {
		descLink := fmt.Sprint(fdPath, fd_list[idx])
		if link, err := os.Readlink(descLink); err == nil && link == expect {
			inodesCache[inodeKey] = &Inode{ FdPath: descLink, Pid: pid }
			addProcEntry(fdPath, fd_list, pid)
			sortProcEntries()
			return true
		}
	}

	return false
}

// lookupPidInProc searches an inode in /proc.
// First it gets the running PIDs and obtains the opened sockets.
// If the inode is not found, then it'll try it again searching in the 
// threads opened by the running PIDs.
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
// /proc/<pid>/fd/ or /proc/<pid>/task/<tid>/fd/ .
func lookupPidDescriptors (fdPath string) []string {
	f, err := os.Open(fdPath)
	if err != nil {
        return nil
    }
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

// getProcPids returns the list of running PIDs, /proc or /proc/<pid>/task/ .
func getProcPids(pidsPath string) (pidList []int) {
	f, err := os.Open(pidsPath)
	if err != nil {
		return pidList
	}
	ls, err := f.Readdir(-1);
	f.Close()
	if err != nil {
		return pidList
	}

	sort.Slice(ls, func(i, j int) bool {
		return ls[i].ModTime().After(ls[j].ModTime())
	})

	for _, f := range ls {
		if f.IsDir() == false {
			continue
		}
		if pid, err := strconv.Atoi(f.Name()); err == nil {
			if pid == ourPid {
				continue
			}
			pidList = append(pidList, []int{pid}...)
		}
	}

	return pidList
}
