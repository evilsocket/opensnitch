package procmon

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
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
	ProcSelf         = "/proc/self/"

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
	mu          *sync.RWMutex
	Statm       *procStatm
	Parent      *Process
	IOStats     *procIOstats
	NetStats    *procNetStats
	Env         map[string]string
	Checksums   map[string]string
	Status      string
	Stat        string
	Stack       string
	Maps        string
	Comm        string
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
	RealPath    string
	CWD         string
	Tree        []*protocol.StringInt
	Descriptors []*procDescriptors
	// Args is the command that the user typed. It MAY contain the absolute path
	// of the binary:
	// $ curl https://...
	//   -> Path: /usr/bin/curl
	//   -> Args: curl https://....
	// $ /usr/bin/curl https://...
	//   -> Path: /usr/bin/curl
	//   -> Args: /usr/bin/curl https://....
	Args      []string
	Starttime int64
	ID        int
	PPID      int
	UID       int
}

// NewProcessEmpty returns a new Process struct with no details.
func NewProcessEmpty(pid int, comm string) *Process {
	p := &Process{
		mu:        &sync.RWMutex{},
		Starttime: time.Now().UnixNano(),
		ID:        pid,
		PPID:      0,
		Comm:      comm,
		Args:      make([]string, 0),
		Env:       make(map[string]string),
		Tree:      make([]*protocol.StringInt, 0),
		IOStats:   &procIOstats{},
		NetStats:  &procNetStats{},
		Statm:     &procStatm{},
		Checksums: make(map[string]string),
	}
	p.pathProc = core.ConcatStrings("/proc/", strconv.Itoa(p.ID))
	p.pathExe = core.ConcatStrings(p.pathProc, "/exe")
	p.pathCwd = core.ConcatStrings(p.pathProc, "/cwd")
	p.pathComm = core.ConcatStrings(p.pathProc, "/comm")
	p.pathCmdline = core.ConcatStrings(p.pathProc, "/cmdline")
	p.pathEnviron = core.ConcatStrings(p.pathProc, "/environ")
	p.pathStatus = core.ConcatStrings(p.pathProc, "/status")
	p.pathStatm = core.ConcatStrings(p.pathProc, "/statm")
	p.pathRoot = core.ConcatStrings(p.pathProc, "/root")
	p.pathMaps = core.ConcatStrings(p.pathProc, "/maps")
	p.pathStat = core.ConcatStrings(p.pathProc, "/stat")
	p.pathMem = core.ConcatStrings(p.pathProc, "/mem")
	p.pathFd = core.ConcatStrings(p.pathProc, "/fd/")
	p.pathIO = core.ConcatStrings(p.pathProc, "/io")

	return p
}

// NewProcess returns a new Process structure.
func NewProcess(pid int, comm string) *Process {
	p := NewProcessEmpty(pid, comm)
	if pid <= 0 {
		return p
	}
	p.GetDetails()
	p.GetParent()
	p.BuildTree()

	return p
}

// NewProcessWithParent returns a new Process structure.
func NewProcessWithParent(pid, ppid int, comm string) *Process {
	p := NewProcessEmpty(pid, comm)
	if pid <= 0 {
		return p
	}
	p.PPID = ppid
	p.GetDetails()
	p.Parent = NewProcess(ppid, comm)

	return p
}

// Lock locks this process for w+r
func (p *Process) Lock() {
	p.mu.Lock()
}

// Unlock unlocks reading from this process
func (p *Process) Unlock() {
	p.mu.Unlock()
}

// RLock locks this process for r
func (p *Process) RLock() {
	p.mu.RLock()
}

// RUnlock unlocks reading from this process
func (p *Process) RUnlock() {
	p.mu.RUnlock()
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
		Pid:         uint64(p.ID),
		Ppid:        uint64(p.PPID),
		Uid:         uint64(p.UID),
		Comm:        p.Comm,
		Path:        p.Path,
		Args:        p.Args,
		Env:         p.Env,
		Cwd:         p.CWD,
		Checksums:   p.Checksums,
		IoReads:     uint64(ioStats.RChar),
		IoWrites:    uint64(ioStats.WChar),
		NetReads:    netStats.ReadBytes,
		NetWrites:   netStats.WriteBytes,
		ProcessTree: p.Tree,
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
	lock.RLock()
	defer lock.RUnlock()

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
