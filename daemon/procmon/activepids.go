package procmon

import (
	"sync"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netlink/procmon"
)

type value struct {
	Process *Process
	//Starttime uniquely identifies a process, it is the 22nd value in /proc/<PID>/stat
	//if another process starts with the same PID, it's Starttime will be unique
	Starttime uint64
}

var (
	activePids     = make(map[uint64]value)
	activePidsLock = sync.RWMutex{}
)

// MonitorProcEvents listen for process events from kernel, via netlink.
func MonitorProcEvents(stop <-chan struct{}) {
	log.Debug("MonitorProcEvents start")
	for {
		select {
		case <-stop:
			goto Exit
		case ev := <-procmon.ProcEventsChannel:
			if ev.IsExec() {
				onExecEvent(ev)
			} else if ev.IsExit() {
				p, _, found := EventsCache.IsInStore(int(ev.PID), nil)
				if found && p.Proc.IsAlive() == false {
					EventsCache.Delete(p.Proc.ID)
				}
			}
		}
	}
Exit:
	log.Debug("MonitorProcEvents stopped")
}

// onExecEvent builds the process that has just exec'd and caches it. It
// returns the process so tests can inspect it.
func onExecEvent(ev procmon.ProcEvent) *Process {
	// we don't receive the path of the process, therefore we need to discover it,
	// to check if the PID has replaced the PPID.
	// NewProcess reads the details, the ancestors and the tree once. On exec
	// PID == TGID, so building the TGID as the parent duplicated that work.
	proc := NewProcess(int(ev.PID), "")

	// Parent is nil when /proc/<pid>/stat could not be read (the process has
	// already exited). The arguments are evaluated at any log level.
	parentPath := ""
	if proc.Parent != nil {
		parentPath = proc.Parent.Path
	}
	log.Debug("[procmon exec event] %d, pid:%d tgid:%d %s, %s -> %s\n", ev.TimeStamp, ev.PID, ev.TGID, proc.Comm, proc.Path, parentPath)
	if item, needsUpdate, found := EventsCache.IsInStore(int(ev.PID), proc); found {
		if needsUpdate {
			EventsCache.Update(&item.Proc, proc)
		}
		log.Debug("[procmon exec event inCache] %d, pid:%d tgid:%d\n", ev.TimeStamp, ev.PID, ev.TGID)
		return proc
	}
	EventsCache.Add(proc)
	return proc
}
