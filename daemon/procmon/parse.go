package procmon

import (
	"fmt"
	"os"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon/audit"
)

func getPIDFromAuditEvents(inode int, inodeKey string, expect string) (int, int) {
	audit.Lock.RLock()
	defer audit.Lock.RUnlock()

	auditEvents := audit.GetEvents()
	for n := 0; n < len(auditEvents); n++ {
		pid := auditEvents[n].Pid
		if inodeFound("/proc/", expect, inodeKey, inode, pid) {
			return pid, n
		}
	}
	for n := 0; n < len(auditEvents); n++ {
		ppid := auditEvents[n].PPid
		if inodeFound("/proc/", expect, inodeKey, inode, ppid) {
			return ppid, n
		}
	}
	return -1, -1
}

// GetPIDFromINode tries to get the PID from a socket inode following these steps:
// 1. Get the PID from the cache of Inodes.
// 2. Get the PID from the cache of PIDs.
// 3. Look for the PID using one of these methods:
//    - ftrace: listening processes execs/exits from /sys/kernel/debug/tracing/
//    - audit:  listening for socket creation from auditd.
//    - proc:   search /proc
//
// If the PID is not found by one of the 2 first methods, it'll try it using /proc.
func GetPIDFromINode(inode int, inodeKey string) int {
	found := -1
	if inode <= 0 {
		return found
	}
	start := time.Now()

	expect := fmt.Sprintf("socket:[%d]", inode)
	if cachedPidInode := inodesCache.getPid(inodeKey); cachedPidInode != -1 {
		log.Debug("Inode found in cache: %v %v %v %v", time.Since(start), inodesCache.getPid(inodeKey), inode, inodeKey)
		return cachedPidInode
	}

	cachedPid, pos := pidsCache.getPid(inode, inodeKey, expect)
	if cachedPid != -1 {
		log.Debug("Socket found in known pids %v, pid: %d, inode: %d, pos: %d, pids in cache: %d", time.Since(start), cachedPid, inode, pos, pidsCache.countItems())
		pidsCache.sort(cachedPid)
		inodesCache.add(inodeKey, "", cachedPid)
		return cachedPid
	}

	if MethodIsAudit() {
		if aPid, pos := getPIDFromAuditEvents(inode, inodeKey, expect); aPid != -1 {
			log.Debug("PID found via audit events: %v, position: %d", time.Since(start), pos)
			return aPid
		}
	} else if MethodIsFtrace() && IsWatcherAvailable() {
		forEachProcess(func(pid int, path string, args []string) bool {
			if inodeFound("/proc/", expect, inodeKey, inode, pid) {
				found = pid
				return true
			}
			// keep looping
			return false
		})
	}
	if found == -1 || methodIsProc() {
		found = lookupPidInProc("/proc/", expect, inodeKey, inode)
	}
	log.Debug("new pid lookup took (%d): %v", found, time.Since(start))

	return found
}

// FindProcess checks if a process exists given a PID.
// If it exists in /proc, a new Process{} object is returned with  the details
// to identify a process (cmdline, name, environment variables, etc).
func FindProcess(pid int, interceptUnknown bool) *Process {
	if interceptUnknown && pid == -100 {
		return NewProcess(-100, "Linux kernel")
	}
	if interceptUnknown && pid < 0 {
		return NewProcess(0, "")
	}

	if proc := findProcessInActivePidsCache(uint64(pid)); proc != nil {
		return proc
	}

	if MethodIsAudit() {
		if aevent := audit.GetEventByPid(pid); aevent != nil {
			audit.Lock.RLock()
			proc := NewProcess(pid, aevent.ProcPath)
			proc.readCmdline()
			proc.setCwd(aevent.ProcDir)
			audit.Lock.RUnlock()
			// if the proc dir contains non alhpa-numeric chars the field is empty
			if proc.CWD == "" {
				proc.readCwd()
			}
			proc.readEnv()
			proc.cleanPath()

			addToActivePidsCache(uint64(pid), proc)
			return proc
		}
	}

	linkName := fmt.Sprint("/proc/", pid, "/exe")
	if _, err := os.Lstat(linkName); err != nil {
		return nil
	}

	if link, err := os.Readlink(linkName); err == nil {
		proc := NewProcess(pid, link)

		proc.readCmdline()
		proc.readCwd()
		proc.readEnv()
		proc.cleanPath()

		addToActivePidsCache(uint64(pid), proc)
		return proc
	}
	return nil
}
