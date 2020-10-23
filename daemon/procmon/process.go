package procmon

import (
	"time"

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

// Reload stops the current monitor method and starts it again.
func Reload() {
	End()
	time.Sleep(1 * time.Second)
	Init()
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
	lock.Lock()
	defer lock.Unlock()

	if monitorMethod == MethodAudit {
		audit.Stop()
	} else if monitorMethod == MethodFtrace {
		go Stop()
	}
}

// Init starts parsing connections using the method specified.
func Init() {
	if methodIsFtrace() {
		if err := Start(); err == nil {
			return
		}
	} else if methodIsAudit() {
		if c, err := audit.Start(); err == nil {
			go audit.Reader(c, (chan<- audit.Event)(audit.EventChan))
			return
		}
	}
	log.Info("Process monitor parsing /proc")
	SetMonitorMethod(MethodProc)
}
