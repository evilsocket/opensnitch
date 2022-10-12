package procmon

import (
	"time"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

var (
	cacheMonitorsRunning = false
)

// monitor method supported types
const (
	MethodFtrace = "ftrace"
	MethodProc   = "proc"
	MethodAudit  = "audit"
	MethodEbpf   = "ebpf"
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

type procNetStats struct {
	ReadBytes  uint64
	WriteBytes uint64
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
	ID   int
	PPID int
	UID  int
	Comm string
	// Path is the absolute path to the binary
	Path string
	// Args is the command that the user typed. It MAY contain the absolute path
	// of the binary:
	// $ curl https://...
	//   -> Path: /usr/bin/curl
	//   -> Args: curl https://....
	// $ /usr/bin/curl https://...
	//   -> Path: /usr/bin/curl
	//   -> Args: /usr/bin/curl https://....
	Args        []string
	Env         map[string]string
	CWD         string
	Descriptors []*procDescriptors
	IOStats     *procIOstats
	NetStats    *procNetStats
	Status      string
	Stat        string
	Statm       *procStatm
	Stack       string
	Maps        string
}

// NewProcess returns a new Process structure.
func NewProcess(pid int, comm string) *Process {
	return &Process{
		ID:       pid,
		Comm:     comm,
		Args:     make([]string, 0),
		Env:      make(map[string]string),
		IOStats:  &procIOstats{},
		NetStats: &procNetStats{},
		Statm:    &procStatm{},
	}
}

//Serialize transforms a Process object to gRPC protocol object
func (p *Process) Serialize() *protocol.Process {
	ioStats := p.IOStats
	netStats := p.NetStats
	if ioStats == nil {
		ioStats = &procIOstats{}
	}
	if netStats == nil {
		netStats = &procNetStats{}
	}
	return &protocol.Process{
		Pid:       uint64(p.ID),
		Ppid:      uint64(p.PPID),
		Uid:       uint64(p.UID),
		Comm:      p.Comm,
		Path:      p.Path,
		Args:      p.Args,
		Env:       p.Env,
		Cwd:       p.CWD,
		IoReads:   uint64(ioStats.RChar),
		IoWrites:  uint64(ioStats.WChar),
		NetReads:  netStats.ReadBytes,
		NetWrites: netStats.WriteBytes,
	}
}

// SetMonitorMethod configures a new method for parsing connections.
func SetMonitorMethod(newMonitorMethod string) {
	lock.Lock()
	defer lock.Unlock()

	monitorMethod = newMonitorMethod
}

// GetMonitorMethod configures a new method for parsing connections.
func GetMonitorMethod() string {
	lock.Lock()
	defer lock.Unlock()

	return monitorMethod
}

// MethodIsEbpf returns if the process monitor method is eBPF.
func MethodIsEbpf() bool {
	lock.RLock()
	defer lock.RUnlock()

	return monitorMethod == MethodEbpf
}

// MethodIsFtrace returns if the process monitor method is eBPF.
func MethodIsFtrace() bool {
	lock.RLock()
	defer lock.RUnlock()

	return monitorMethod == MethodFtrace
}

// MethodIsAudit returns if the process monitor method is eBPF.
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
