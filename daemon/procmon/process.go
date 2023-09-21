package procmon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

var (
	lock             = sync.RWMutex{}
	monitorMethod    = MethodProc
	Ctx, CancelTasks = context.WithCancel(context.Background())
)

// monitor method supported types
const (
	MethodProc  = "proc"
	MethodAudit = "audit"
	MethodEbpf  = "ebpf"

	KernelConnection = "Kernel connection"

	HashMD5  = "process.hash.md5"
	HashSHA1 = "process.hash.sha1"
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
	ModTime time.Time
	Name    string
	SymLink string
	Size    int64
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
	Checksums   map[string]string
	Env         map[string]string
	Descriptors []*procDescriptors
	Parent      *Process
	IOStats     *procIOstats
	NetStats    *procNetStats
	Statm       *procStatm

	// Args is the command that the user typed. It MAY contain the absolute path
	// of the binary:
	// $ curl https://...
	//   -> Path: /usr/bin/curl
	//   -> Args: curl https://....
	// $ /usr/bin/curl https://...
	//   -> Path: /usr/bin/curl
	//   -> Args: /usr/bin/curl https://....
	Args   []string
	Status string
	Stat   string
	Stack  string
	Maps   string
	Comm   string

	pathProc    string
	pathComm    string
	pathExe     string
	pathCmdline string
	pathCwd     string
	pathEnviron string
	pathRoot    string
	pathFd      string
	pathStatus  string
	pathStatm   string
	pathStat    string
	pathMaps    string
	pathMem     string
	pathIO      string

	// Path is the absolute path to the binary
	Path string

	// RealPath is the path to the binary taking into account its root fs.
	// The simplest form of accessing the RealPath is by prepending /proc/<pid>/root/ to the path:
	// /usr/bin/curl -> /proc/<pid>/root/usr/bin/curl
	RealPath  string
	CWD       string
	Starttime int64
	ID        int
	PPID      int
	UID       int
}

// NewProcess returns a new Process structure.
func NewProcess(pid int, comm string) *Process {

	p := &Process{
		Starttime: time.Now().UnixNano(),
		ID:        pid,
		Comm:      comm,
		Args:      make([]string, 0),
		Env:       make(map[string]string),
		IOStats:   &procIOstats{},
		NetStats:  &procNetStats{},
		Statm:     &procStatm{},
		Checksums: make(map[string]string),
	}
	if pid <= 0 {
		return p
	}
	p.pathProc = fmt.Sprint("/proc/", p.ID)
	p.pathExe = fmt.Sprint(p.pathProc, "/exe")
	p.pathCwd = fmt.Sprint(p.pathProc, "/cwd")
	p.pathComm = fmt.Sprint(p.pathProc, "/comm")
	p.pathCmdline = fmt.Sprint(p.pathProc, "/cmdline")
	p.pathEnviron = fmt.Sprint(p.pathProc, "/environ")
	p.pathStatus = fmt.Sprint(p.pathProc, "/status")
	p.pathStatm = fmt.Sprint(p.pathProc, "/statm")
	p.pathRoot = fmt.Sprint(p.pathProc, "/root")
	p.pathMaps = fmt.Sprint(p.pathProc, "/maps")
	p.pathStat = fmt.Sprint(p.pathProc, "/stat")
	p.pathMem = fmt.Sprint(p.pathProc, "/mem")
	p.pathFd = fmt.Sprint(p.pathProc, "/fd/")
	p.pathIO = fmt.Sprint(p.pathProc, "/io")

	return p
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
		Checksums: p.Checksums,
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
