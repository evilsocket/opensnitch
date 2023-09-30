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
				proc := NewProcessWithParent(int(ev.PID), int(ev.TGID), "")

				log.Debug("[procmon exec event] %d, pid:%d tgid:%d %s, %s -> %s\n", ev.TimeStamp, ev.PID, ev.TGID, proc.Comm, proc.Path, proc.Parent.Path)
				if _, needsUpdate, found := EventsCache.IsInStore(int(ev.PID), proc); found {
					if needsUpdate {
						EventsCache.ComputeChecksums(proc)
						EventsCache.UpdateItemDetails(proc)
					}
					log.Debug("[procmon exec event inCache] %d, pid:%d tgid:%d\n", ev.TimeStamp, ev.PID, ev.TGID)
					continue
				}
				// adding item to cache in 2 steps:
				// 1. with basic information, to have it readily available
				// 2. getting the rest of the process details
				EventsCache.Add(proc)
				EventsCache.UpdateItemDetails(proc)
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
