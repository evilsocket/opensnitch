package procmon

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/core"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/procmon/audit"
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
	return -1, -1
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

	cachedPid, pos := getPidFromCache(inode, inodeKey, expect)
	if cachedPid != -1 {
		log.Debug("Socket found in known pids %v, pid: %d, inode: %d, pids in cache: %d", time.Since(start), cachedPid, inode, "pos", pos, len(pidsCache))
		sortProcEntries()
		return cachedPid
	}

	if MonitorMethod == MethodAudit {
		if aPid, pos := getPIDFromAuditEvents(inode, inodeKey, expect); aPid != -1 {
			log.Debug("PID found via audit events", time.Since(start), "position", pos)
			return aPid
		}
	} else if MonitorMethod == MethodFtrace && IsWatcherAvailable() {
		forEachProcess(func(pid int, path string, args []string) bool {
			if inodeFound("/proc/", expect, inodeKey, inode, pid) {
				found = pid
				return true
			}
			// keep looping
			return false
		})
	}
	if found == -1 || MonitorMethod == MethodProc {
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
	if MonitorMethod == MethodAudit {
		if aevent := audit.GetEventByPid(pid); aevent != nil {
			audit.Lock.RLock()
			proc := NewProcess(pid, strings.Split(aevent.ProcPath, " ")[0])
			proc.Args = strings.Split(strings.Replace(aevent.ProcCmdLine, "\x00", " ", -1), " ")
			audit.Lock.RUnlock()
			parseEnv(proc)

			return proc
		}
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
