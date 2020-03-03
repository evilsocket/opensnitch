package procmon

import (
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/procmon/audit"
)

type Process struct {
	ID   int
	Path string
	Args []string
	Env  map[string]string
}

func NewProcess(pid int, path string) *Process {
	return &Process{
		ID:   pid,
		Path: path,
		Args: make([]string, 0),
		Env:  make(map[string]string),
	}
}

func End() {
	if MonitorMethod == MethodAudit {
		audit.Stop()
	} else if MonitorMethod == MethodFtrace {
		go Stop()
	}
}

func Init() {
	if MonitorMethod == MethodFtrace {
		if err := Start(); err == nil {
			return
		}
	} else if MonitorMethod == MethodAudit {
		if c, err := audit.Start(); err == nil {
			go audit.Reader(c, (chan<- audit.Event)(audit.EventChan))
			return
		}
	}
	log.Info("Process monitor parsing /proc")
	MonitorMethod = MethodProc
}
