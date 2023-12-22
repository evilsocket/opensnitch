package monitor

import (
	"context"

	"github.com/evilsocket/opensnitch/daemon/log"
	netlinkProcmon "github.com/evilsocket/opensnitch/daemon/netlink/procmon"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/procmon/audit"
	"github.com/evilsocket/opensnitch/daemon/procmon/ebpf"
)

var (
	cacheMonitorsRunning  = false
	netlinkProcmonRunning = false
	ctx, cancelTasks      = context.WithCancel(context.Background())
)

// List of errors that this package may return.
const (
	NoError = iota
	ProcFsErr
	AuditdErr
	EbpfErr
	EbpfEventsErr
)

// Error wraps the type of error with its message
type Error struct {
	What int
	Msg  error
}

func startProcMonitors() {
	if netlinkProcmonRunning == false {
		ctx, cancelTasks = context.WithCancel(context.Background())
		for i := 0; i < 4; i++ {
			go procmon.MonitorProcEvents(ctx.Done())
		}
		go netlinkProcmon.ProcEventsMonitor(ctx.Done())
		netlinkProcmonRunning = true
	}
}

func stopProcMonitors() {
	if netlinkProcmonRunning {
		cancelTasks()
		netlinkProcmonRunning = false
	}
}

// ReconfigureMonitorMethod configures a new method for parsing connections.
func ReconfigureMonitorMethod(newMonitorMethod, ebpfModulesPath string) *Error {
	if procmon.GetMonitorMethod() == newMonitorMethod {
		return nil
	}

	oldMethod := procmon.GetMonitorMethod()
	if oldMethod == "" {
		oldMethod = procmon.MethodProc
	}
	End()
	procmon.SetMonitorMethod(newMonitorMethod)
	// if the new monitor method fails to start, rollback the change and exit
	// without saving the configuration. Otherwise we can end up with the wrong
	// monitor method configured and saved to file.
	err := Init(ebpfModulesPath)
	if err.What > NoError {
		log.Error("Reconf() -> Init() error: %v", err)
		procmon.SetMonitorMethod(oldMethod)
		return err
	}

	return nil
}

// End stops the way of parsing new connections.
func End() {
	stopProcMonitors()
	if procmon.MethodIsAudit() {
		audit.Stop()
	} else if procmon.MethodIsEbpf() {
		ebpf.Stop()
	}
}

// Init starts parsing connections using the method specified.
func Init(ebpfModulesPath string) (errm *Error) {
	errm = &Error{}

	if cacheMonitorsRunning == false {
		go procmon.CacheCleanerTask()
		cacheMonitorsRunning = true
	}

	if procmon.MethodIsEbpf() {
		err := ebpf.Start(ebpfModulesPath)
		if err == nil {
			log.Info("Process monitor method ebpf")
			return errm
		}
		// ebpf main module loaded, we can use ebpf

		// XXX: this will have to be rewritten when we'll have more events (bind, listen, etc)
		if err.What == ebpf.EventsNotAvailable {
			log.Info("Process monitor method ebpf")
			log.Warning("opensnitch-procs.o not available: %s", err.Msg)

			startProcMonitors()
			return errm
		}
		// we need to stop this method even if it has failed to start, in order to clean up the kprobes
		// It helps with the error "cannot write...kprobe_events: file exists".
		ebpf.Stop()
		errm.What = err.What
		errm.Msg = err.Msg
		log.Warning("error starting ebpf monitor method: %v", err)

	} else if procmon.MethodIsAudit() {
		auditConn, err := audit.Start()
		if err == nil {
			log.Info("Process monitor method audit")
			go audit.Reader(auditConn, (chan<- audit.Event)(audit.EventChan))
			return &Error{AuditdErr, err}
		}
		errm.What = AuditdErr
		errm.Msg = err
		log.Warning("error starting audit monitor method: %v", err)
	}

	startProcMonitors()
	// if any of the above methods have failed, fallback to proc
	log.Info("Process monitor method /proc")
	procmon.SetMonitorMethod(procmon.MethodProc)
	return errm
}
