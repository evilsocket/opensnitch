package procmon

import (
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/procmon/audit"
)

// Process holds the information of a process.
type Process struct {
	ID   int
	Path string
	Args []string
	Env  map[string]string
	CWD  string
}

// NewProcess returns a new Process structure.
func NewProcess(pid int, path string) *Process {
	return &Process{
		ID:   pid,
		Path: path,
		Args: make([]string, 0),
		Env:  make(map[string]string),
	}
}

// SetMonitorMethod configures a new method for parsing connections.
func SetMonitorMethod(newMonitorMethod string) {
	lock.Lock()
	defer lock.Unlock()

	monitorMethod = newMonitorMethod
}

func methodIsFtrace() bool {
	lock.RLock()
	defer lock.RUnlock()

	return monitorMethod == MethodFtrace
}

func methodIsAudit() bool {
	lock.RLock()
	defer lock.RUnlock()

	return monitorMethod == MethodAudit
}

func methodIsProc() bool {
	lock.RLock()
	defer lock.RUnlock()

	return monitorMethod == MethodProc
}

// End stops the way of parsing new connections.
func End() {
	if methodIsAudit() {
		audit.Stop()
	} else if methodIsFtrace() {
		go func() {
			if err := Stop(); err != nil {
				log.Warning("procmon.End() stop ftrace error: %v", err)
			}
		}()
	}
}

// Init starts parsing connections using the method specified.
func Init() {
	if methodIsFtrace() {
		err := Start()
		if err == nil {
			log.Info("Process monitor method ftrace")
			return
		}
		log.Warning("error starting ftrace monitor method: %v", err)

	} else if methodIsAudit() {
		auditConn, err := audit.Start()
		if err == nil {
			log.Info("Process monitor method audit")
			go audit.Reader(auditConn, (chan<- audit.Event)(audit.EventChan))
			return
		}
		log.Warning("error starting audit monitor method: %v", err)
	}

	// if any of the above methods have failed, fallback to proc
	log.Info("Process monitor method /proc")
	SetMonitorMethod(MethodProc)
}
