package procmon

import (
	"runtime"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

var (
	// ProcEventsChannel channel of events to read
	ProcEventsChannel = make(chan ProcEvent)
)

// ProcEvent represents the struct returned from kernel
type ProcEvent struct {
	ev netlink.ProcEvent

	TimeStamp uint64
	PID       uint32
	PPID      uint32
	TGID      uint32
	PTGID     uint32
}

// ProcEventsMonitor listens for process events from kernel.
// We listen for events via netlink, from the Process Events Conector:
// https://lwn.net/Articles/157150/
// The kernel must have the options CONFIG_CONECTOR and CONFIG_PROC_EVENTS enabled.
func ProcEventsMonitor(done <-chan struct{}) {
	log.Info("ProcEventMonitor started\n")
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid1ns, err := netns.GetFromPid(1)
	if err != nil {
		log.Warning("unable to start netlink.ProcEventMonitor (0): %s", err)
		return
	}

	err = netns.Set(pid1ns)
	if err != nil {
		log.Warning("unable to start netlink.ProcEventMonitor (1): %s", err)
		return
	}

	ch := make(chan netlink.ProcEvent)
	errChan := make(chan error)
	if err := netlink.ProcEventMonitor(ch, done, errChan); err != nil {
		log.Warning("unable to start netlink.ProcEventMonitor (2): %s", err)
		return
	}

	for {
		select {
		case <-done:
			goto Exit
		case errc := <-errChan:
			// We may receive "no buffer space available" when:
			// - the daemon is stopped (ptrace, signal, etc).
			// - sometimes after coming back from suspend.
			log.Error("ProcEventMonitor error: %s", errc)
			goto Error
		case e := <-ch:
			p := NewProcEvent(e)
			if !p.IsExec() && !p.IsExit() {
				// Msg may be nil in case of error
				if p.ev.Msg == nil {
					log.Warning("ProcEventMonitor Msg == nil")
					goto Error
				}
				continue
			}
			ProcEventsChannel <- p
		}
	}
Error:
	log.Info("reinitiating ProcEventMonitor")
	time.Sleep(time.Second)
	ProcEventsMonitor(done)
	return
Exit:
	log.Debug("netlink.ProcEventsMonitor stopped")
}

// NewProcEvent returns a new event received from kernel
func NewProcEvent(ev netlink.ProcEvent) ProcEvent {
	pv := ProcEvent{ev: ev, TimeStamp: ev.Timestamp}
	if pv.IsExec() {
		if execEv, ok := pv.Msg().(*netlink.ExecProcEvent); ok {
			pv.PID = execEv.ProcessPid
			pv.TGID = execEv.ProcessTgid
		}
	} else if pv.IsExit() {
		if exitEv, ok := pv.Msg().(*netlink.ExitProcEvent); ok {
			pv.PID = exitEv.ProcessPid
			pv.PPID = exitEv.ParentPid
			pv.TGID = exitEv.ProcessTgid
			pv.PTGID = exitEv.ParentTgid
		}
	}
	/*else if pv.IsFork() {
		if forkEv, ok := pv.Msg().(*netlink.ForkProcEvent); ok {
			pv.PID = forkEv.ChildPid
			pv.PPID = forkEv.ParentPid
			pv.TGID = forkEv.ChildTgid
			pv.PTGID = forkEv.ParentTgid
		}

	} else if pv.IsComm() {
	fmt.Printf("COMM: %d\n", ev.Msg.Pid())
	if commEv, ok := pv.Msg().(*netlink.CommProcEvent); ok {
		fmt.Println("COMM EVENT ->", string(commEv.Comm[:]))
	}
	*/
	return pv
}

// Msg returns the message received from netlink
func (pe *ProcEvent) Msg() interface{} {
	return pe.ev.Msg
}

// Pid returns the pid of the event
func (pe *ProcEvent) Pid() uint32 {
	return pe.ev.Msg.Pid()
}

// IsFork returns if the event is fork
func (pe *ProcEvent) IsFork() bool {
	return pe.ev.What == netlink.PROC_EVENT_FORK
}

// IsExec returns if the event is exec
func (pe *ProcEvent) IsExec() bool {
	return pe.ev.What == netlink.PROC_EVENT_EXEC
}

// IsComm returns if the event is comm
func (pe *ProcEvent) IsComm() bool {
	return pe.ev.What == netlink.PROC_EVENT_COMM
}

// IsExit returns if the event is exit
func (pe *ProcEvent) IsExit() bool {
	return pe.ev.What == netlink.PROC_EVENT_EXIT
}
