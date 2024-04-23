package procmon

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"golang.org/x/sys/unix"
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

// ..
const (
	ProcID = iota
	Comm
	Cmdline
	Exe
	Cwd
	Environ
	Root
	Status
	Statm
	Stat
	Mem
	Maps
	Fd
	IO
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

type procBytes struct {
	sent  uint64
	recv  uint64
	proto uint8
	fam   uint8
}

// Process holds the details of a process.
type Process struct {
	mu        *sync.RWMutex
	Statm     *procStatm
	Parent    *Process
	IOStats   *procIOstats
	NetStats  *procNetStats
	Env       map[string]string
	BytesSent map[string]uint64
	BytesRecv map[string]uint64
	Checksums map[string]string
	CWD       string
	Status    string
	Stat      string
	Stack     string
	Maps      string
	Comm      string

	// Path is the absolute path to the binary
	Path string

	// RealPath is the path to the binary taking into account its root fs.
	// The simplest form of accessing the RealPath is by prepending /proc/<pid>/root/ to the path:
	// /usr/bin/curl -> /proc/<pid>/root/usr/bin/curl
	RealPath string

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
	procPath  []string
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
		procPath:  make([]string, 14),
		Env:       make(map[string]string),
		BytesSent: make(map[string]uint64, 2),
		BytesRecv: make(map[string]uint64, 2),
		Tree:      make([]*protocol.StringInt, 0),
		IOStats:   &procIOstats{},
		NetStats:  &procNetStats{},
		Statm:     &procStatm{},
		Checksums: make(map[string]string),
	}

	p.procPath[ProcID] = core.ConcatStrings("/proc/", strconv.Itoa(p.ID))
	p.procPath[Exe] = core.ConcatStrings(p.procPath[ProcID], "/exe")
	p.procPath[Cwd] = core.ConcatStrings(p.procPath[ProcID], "/cwd")
	p.procPath[Comm] = core.ConcatStrings(p.procPath[ProcID], "/comm")
	p.procPath[Cmdline] = core.ConcatStrings(p.procPath[ProcID], "/cmdline")
	p.procPath[Environ] = core.ConcatStrings(p.procPath[ProcID], "/environ")
	p.procPath[Status] = core.ConcatStrings(p.procPath[ProcID], "/status")
	p.procPath[Statm] = core.ConcatStrings(p.procPath[ProcID], "/statm")
	p.procPath[Root] = core.ConcatStrings(p.procPath[ProcID], "/root")
	p.procPath[Maps] = core.ConcatStrings(p.procPath[ProcID], "/maps")
	p.procPath[Stat] = core.ConcatStrings(p.procPath[ProcID], "/stat")
	p.procPath[Mem] = core.ConcatStrings(p.procPath[ProcID], "/mem")
	p.procPath[Fd] = core.ConcatStrings(p.procPath[ProcID], "/fd/")
	p.procPath[IO] = core.ConcatStrings(p.procPath[ProcID], "/io")

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

// AddBytes accumulates the bytes sent by this process
func (p *Process) AddBytes(fam uint8, proto uint32, sent, recv uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	protoStr := "tcp"
	if proto == unix.IPPROTO_UDP {
		protoStr = "udp"
	}
	family := ""
	if fam == unix.AF_INET6 {
		family = "6"
	}

	p.BytesSent[protoStr+family] += recv
	p.BytesRecv[protoStr+family] += recv
}

// Serialize transforms a Process object to gRPC protocol object
func (p *Process) Serialize() *protocol.Process {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ioStats := p.IOStats
	netStats := p.NetStats
	if ioStats == nil {
		ioStats = &procIOstats{}
	}
	if netStats == nil {
		netStats = &procNetStats{}
	}

	// maps are referenced data types, we cannot assign a map to another
	// an expect to be a copy.
	bsent := make(map[string]uint64, len(p.BytesSent))
	brecv := make(map[string]uint64, len(p.BytesRecv))
	for k, v := range p.BytesSent {
		bsent[k] = v
	}
	for k, v := range p.BytesRecv {
		brecv[k] = v
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
		BytesSent: bsent,
		BytesRecv: brecv,
		Tree:      p.Tree,
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
