package procmon

import (
	"time"
)

var (
	cacheMonitorsRunning = false
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

func MethodIsEbpf() bool {
	lock.RLock()
	defer lock.RUnlock()

	return monitorMethod == MethodEbpf
}

func MethodIsFtrace() bool {
	lock.RLock()
	defer lock.RUnlock()

	return monitorMethod == MethodFtrace
}

func MethodIsAudit() bool {
	lock.RLock()
	defer lock.RUnlock()

	return monitorMethod == MethodAudit
}

func methodIsProc() bool {
	lock.RLock()
	defer lock.RUnlock()

	return monitorMethod == MethodProc
}
