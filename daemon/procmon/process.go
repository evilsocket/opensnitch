package procmon

import (
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon/audit"
)

// man 5 proc; man procfs
type procIOstats struct {
	RChar        int64
	WChar        int64
	SyscallRead  int64
	SyscallWrite int64
	ReadBytes    int64
	WriteBytes   int64
}

type procDescriptors struct {
	Name    string
	SymLink string
	Size    int64
	ModTime time.Time
}

type procStatm struct {
	Size     int64
	Resident int64
	Shared   int64
	Text     int64
	Lib      int64
	Data     int64 // data + stack
	Dt       int
}

// Process holds the details of a process.
type Process struct {
	ID          int
	Path        string
	Args        []string
	Env         map[string]string
	CWD         string
	Descriptors []*procDescriptors
	IOStats     *procIOstats
	Status      string
	Stat        string
	Statm       *procStatm
	Stack       string
	Maps        string
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
	go monitorActivePids()
}
