package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	elf "github.com/iovisor/gobpf/elf"
	"github.com/vishvananda/netlink"
)

//contains pointers to ebpf maps for a given protocol (tcp/udp/v6)
type ebpfMapsForProto struct {
	bpfmap *elf.Map
}

//Not in use, ~4usec faster lookup compared to m.LookupElement()

//mimics union bpf_attr's anonymous struct used by BPF_MAP_*_ELEM commands
//from <linux_headers>/include/uapi/linux/bpf.h
type bpf_lookup_elem_t struct {
	map_fd uint64 //even though in bpf.h its type is __u32, we must make it 8 bytes long
	//because "key" is of type __aligned_u64, i.e. "key" must be aligned on an 8-byte boundary
	key   uintptr
	value uintptr
}

type alreadyEstablishedConns struct {
	TCP   map[*daemonNetlink.Socket]int
	TCPv6 map[*daemonNetlink.Socket]int
	sync.RWMutex
}

// list of returned errors
const (
	NoError = iota
	NotAvailable
	EventsNotAvailable
)

// Error returns the error type and a message with the explanation
type Error struct {
	What int // 1 global error, 2 events error, 3 ...
	Msg  error
}

var (
	m, perfMod  *elf.Module
	lock        = sync.RWMutex{}
	mapSize     = uint(12000)
	ebpfMaps    map[string]*ebpfMapsForProto
	modulesPath string

	//connections which were established at the time when opensnitch started
	alreadyEstablished = alreadyEstablishedConns{
		TCP:   make(map[*daemonNetlink.Socket]int),
		TCPv6: make(map[*daemonNetlink.Socket]int),
	}
	ctxTasks    context.Context
	cancelTasks context.CancelFunc
	running     = false

	maxKernelEvents = 32768
	kernelEvents    = make(chan interface{}, maxKernelEvents)

	// list of local addresses of this machine
	localAddresses = make(map[string]netlink.Addr)

	hostByteOrder binary.ByteOrder
)

//Start installs ebpf kprobes
func Start(modPath string) *Error {
	modulesPath = modPath

	setRunning(false)
	if err := mountDebugFS(); err != nil {
		return &Error{
			NotAvailable,
			fmt.Errorf("ebpf.Start: mount debugfs error. Report on github please: %s", err),
		}
	}
	var err error
	m, err = core.LoadEbpfModule("opensnitch.o", modulesPath)
	if err != nil {
		dispatchErrorEvent(fmt.Sprint("[eBPF]: ", err.Error()))
		return &Error{NotAvailable, fmt.Errorf("[eBPF] Error loading opensnitch.o: %s", err.Error())}
	}
	m.EnableOptionCompatProbe()

	// if previous shutdown was unclean, then we must remove the dangling kprobe
	// and install it again (close the module and load it again)

	if err := m.EnableKprobes(0); err != nil {
		m.Close()
		if err := m.Load(nil); err != nil {
			return &Error{NotAvailable, fmt.Errorf("eBPF failed to load /etc/opensnitchd/opensnitch.o (2): %v", err)}
		}
		if err := m.EnableKprobes(0); err != nil {
			return &Error{NotAvailable, fmt.Errorf("eBPF error when enabling kprobes: %v", err)}
		}
	}
	determineHostByteOrder()

	ebpfMaps = map[string]*ebpfMapsForProto{
		"tcp": {
			bpfmap: m.Map("tcpMap")},
		"tcp6": {
			bpfmap: m.Map("tcpv6Map")},
		"udp": {
			bpfmap: m.Map("udpMap")},
		"udp6": {
			bpfmap: m.Map("udpv6Map")},
	}
	for prot, mfp := range ebpfMaps {
		if mfp.bpfmap == nil {
			return &Error{NotAvailable, fmt.Errorf("eBPF module opensnitch.o malformed, bpfmap[%s] nil", prot)}
		}
	}

	ctxTasks, cancelTasks = context.WithCancel(context.Background())
	ebpfCache = NewEbpfCache()
	errf := initEventsStreamer()

	saveEstablishedConnections(uint8(syscall.AF_INET))
	if core.IPv6Enabled {
		saveEstablishedConnections(uint8(syscall.AF_INET6))
	}

	go monitorCache()
	go monitorMaps()
	go monitorLocalAddresses()
	go monitorAlreadyEstablished()

	setRunning(true)
	return errf
}

func saveEstablishedConnections(commDomain uint8) error {
	// save already established connections
	socketListTCP, err := daemonNetlink.SocketsDump(commDomain, uint8(syscall.IPPROTO_TCP))
	if err != nil {
		log.Debug("eBPF could not dump TCP (%d) sockets via netlink: %v", commDomain, err)
		return err
	}

	for _, sock := range socketListTCP {
		inode := int((*sock).INode)
		pid := procmon.GetPIDFromINode(inode, fmt.Sprint(inode,
			(*sock).ID.Source, (*sock).ID.SourcePort, (*sock).ID.Destination, (*sock).ID.DestinationPort))
		alreadyEstablished.Lock()
		alreadyEstablished.TCP[sock] = pid
		alreadyEstablished.Unlock()
	}
	return nil
}

func setRunning(status bool) {
	lock.Lock()
	defer lock.Unlock()

	running = status
}

// Stop stops monitoring connections using kprobes
func Stop() {
	log.Debug("ebpf.Stop()")
	lock.RLock()
	defer lock.RUnlock()
	if running == false {
		return
	}
	cancelTasks()
	ebpfCache.clear()

	if m != nil {
		m.Close()
	}

	for pm := range perfMapList {
		if pm != nil {
			pm.PollStop()
		}
	}
	for k, mod := range perfMapList {
		if mod != nil {
			mod.Close()
			delete(perfMapList, k)
		}
	}
	if perfMod != nil {
		perfMod.Close()
	}
}

//make bpf() syscall with bpf_lookup prepared by the caller
func makeBpfSyscall(bpf_lookup *bpf_lookup_elem_t) uintptr {
	BPF_MAP_LOOKUP_ELEM := 1 //cmd number
	syscall_BPF := 321       //syscall number
	sizeOfStruct := 40       //sizeof bpf_lookup_elem_t struct

	r1, _, _ := syscall.Syscall(uintptr(syscall_BPF), uintptr(BPF_MAP_LOOKUP_ELEM),
		uintptr(unsafe.Pointer(bpf_lookup)), uintptr(sizeOfStruct))
	return r1
}

func dispatchErrorEvent(what string) {
	log.Error(what)
	dispatchEvent(what)
}

func dispatchEvent(data interface{}) {
	if len(kernelEvents) > maxKernelEvents-1 {
		fmt.Printf("kernelEvents queue full (%d)", len(kernelEvents))
		<-kernelEvents
	}
	select {
	case kernelEvents <- data:
	default:
	}
}

func Events() <-chan interface{} {
	return kernelEvents
}
