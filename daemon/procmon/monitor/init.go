package monitor

import (
	"net"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/procmon/audit"
	"github.com/evilsocket/opensnitch/daemon/procmon/ebpf"
)

var (
	cacheMonitorsRunning = false
)

// ReconfigureMonitorMethod configures a new method for parsing connections.
func ReconfigureMonitorMethod(newMonitorMethod string) error {

	if procmon.GetMonitorMethod() == newMonitorMethod {
		return nil
	}

	oldMethod := procmon.GetMonitorMethod()
	End()
	procmon.SetMonitorMethod(newMonitorMethod)
	// if the new monitor method fails to start, rollback the change and exit
	// without saving the configuration. Otherwise we can end up with the wrong
	// monitor method configured and saved to file.
	if err := Init(); err != nil {
		procmon.SetMonitorMethod(oldMethod)
		return err
	}

	return nil
}

// End stops the way of parsing new connections.
func End() {
	if procmon.MethodIsAudit() {
		audit.Stop()
	} else if procmon.MethodIsEbpf() {
		ebpf.Stop()
	} else if procmon.MethodIsFtrace() {
		go func() {
			if err := procmon.Stop(); err != nil {
				log.Warning("procmon.End() stop ftrace error: %v", err)
			}
		}()
	}
}

// Init starts parsing connections using the method specified.
func Init() (err error) {
	if cacheMonitorsRunning == false {
		go procmon.MonitorActivePids()
		go procmon.CacheCleanerTask()
		cacheMonitorsRunning = true
	}

	if procmon.MethodIsEbpf() {
		err = ebpf.Start()
		if err == nil {
			log.Info("Process monitor method ebpf")
			return nil
		}
		// we need to stop this method even if it has failed to start, in order to clean up the kprobes
		// It helps with the error "cannot write...kprobe_events: file exists".
		ebpf.Stop()
		log.Warning("error starting ebpf monitor method: %v", err)
	} else if procmon.MethodIsFtrace() {
		err = procmon.Start()
		if err == nil {
			log.Info("Process monitor method ftrace")
			return nil
		}
		log.Warning("error starting ftrace monitor method: %v", err)

	} else if procmon.MethodIsAudit() {
		var auditConn net.Conn
		auditConn, err = audit.Start()
		if err == nil {
			log.Info("Process monitor method audit")
			go audit.Reader(auditConn, (chan<- audit.Event)(audit.EventChan))
			return nil
		}
		log.Warning("error starting audit monitor method: %v", err)
	}

	// if any of the above methods have failed, fallback to proc
	log.Info("Process monitor method /proc")
	procmon.SetMonitorMethod(procmon.MethodProc)
	return err
}
