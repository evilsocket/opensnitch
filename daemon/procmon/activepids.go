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
				// we don't receive the path of the process, therefore we need to discover it,
				// to check if the PID has replaced the PPID.
				proc := NewProcess(int(ev.PID), "")
				proc.GetInfo()
				proc.Parent = NewProcess(int(ev.TGID), "")
				proc.Parent.GetInfo()

				log.Debug("[procmon exec event] %d, pid:%d tgid:%d %s, %s -> %s\n", ev.TimeStamp, ev.PID, ev.TGID, proc.Comm, proc.Path, proc.Parent.Path)
				//log.Debug("[procmon exec event] %d, pid:%d tgid:%d\n", ev.TimeStamp, ev.PID, ev.TGID)
				if _, needsHashUpdate, found := EventsCache.IsInStore(int(ev.PID), proc); found {
					// check if this PID has replaced the PPID:
					// systemd, pid:1234 -> curl, pid:1234 -> curl (i.e.: pid 1234) opens x.x.x.x:443
					// Without this, we would display that systemd is connecting to x.x.x.x:443
					// The previous pid+path will still exist as parent of the new child, in proc.Parent
					if needsHashUpdate {
						//log.Debug("[procmon inCache REPLACEMENT] rehashing, new: %d, %s -> inCache: %d -> %s", proc.ID, proc.Path, item.Proc.ID, item.Proc.Path)
						EventsCache.ComputeChecksums(proc)
					}
					log.Debug("[procmon exec event inCache] %d, pid:%d tgid:%d\n", ev.TimeStamp, ev.PID, ev.TGID)
					continue
				}
				EventsCache.Add(*proc)
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
