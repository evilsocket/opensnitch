package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/vishvananda/netlink"
)

// KProbeDefs holds the hooks defined in the main module, for network interception.
type KProbeDefs struct {
	KProbeTCPv4Connect        *ebpf.Program `ebpf:"kprobe__tcp_v4_connect"`
	KretProbeTCPv4Connect     *ebpf.Program `ebpf:"kretprobe__tcp_v4_connect"`
	KProbeTCPv6Connect        *ebpf.Program `ebpf:"kprobe__tcp_v6_connect"`
	KretProbeTCPv6Connect     *ebpf.Program `ebpf:"kretprobe__tcp_v6_connect"`
	KProbeUDPv4Connect        *ebpf.Program `ebpf:"kprobe__udp_sendmsg"`
	KProbeUDPv6Connect        *ebpf.Program `ebpf:"kprobe__udpv6_sendmsg"`
	KProbeIPtunnelXmit        *ebpf.Program `ebpf:"kprobe__iptunnel_xmit"`
	KProbeInetDgramConnect    *ebpf.Program `ebpf:"kprobe__inet_dgram_connect"`
	KretProbeInetDgramConnect *ebpf.Program `ebpf:"kretprobe__inet_dgram_connect"`
}

// MapDefs holds the map definitions of the main module
type MapDefs struct {
	TCPMap   *ebpf.Map `ebpf:"tcpMap"`
	UDPMap   *ebpf.Map `ebpf:"udpMap"`
	TCPv6Map *ebpf.Map `ebpf:"tcpv6Map"`
	UDPv6Map *ebpf.Map `ebpf:"udpv6Map"`
}

// container of hooks and maps
type ebpfDefsT struct {
	KProbeDefs
	MapDefs
}

// contains pointers to ebpf maps for a given protocol (tcp/udp/v6)
type ebpfMapsForProto struct {
	bpfMap *ebpf.Map
}

//Not in use, ~4usec faster lookup compared to m.LookupElement()

// mimics union bpf_attr's anonymous struct used by BPF_MAP_*_ELEM commands
// from <linux_headers>/include/uapi/linux/bpf.h
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
	Msg  error
	What int // 1 global error, 2 events error, 3 ...
}

var (
	m            *ebpf.Collection
	eventsReader *ringbuf.Reader
	ebpfCfg      Config
	lock         = sync.RWMutex{}
	mapSize      = uint(12000)
	ebpfMaps     map[string]*ebpfMapsForProto

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

	// "Losing the reference to the resulting Link (kp) will close the Kprobe and
	// prevent further execution of prog. The Link must be Closed during program
	// shutdown to avoid leaking system resources."
	// https://pkg.go.dev/github.com/cilium/ebpf/link#Kprobe

	// array that holds the reference to every loaded hook.
	hooks          = []link.Link{}
	collectionMaps = make([]*ebpf.Collection, 0)
)

// Start installs ebpf kprobes
func Start(ebpfOpts Config) *Error {
	setConfig(ebpfOpts)
	setRunning(false)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warning("[eBPF] unable to remove memlock")
	}

	var err error
	// load definitions from the elf file.
	m, err = core.LoadEbpfModule("opensnitch.o", ebpfCfg.ModulesPath)
	if err != nil {
		dispatchErrorEvent(fmt.Sprint("[eBPF]: ", err.Error()))
		return &Error{fmt.Errorf("[eBPF] Error loading opensnitch.o: %s", err.Error()), NotAvailable}
	}
	determineHostByteOrder()

	// create objects from the definitions
	ebpfMod := ebpfDefsT{}
	if err := m.Assign(&ebpfMod); err != nil {
		dispatchErrorEvent(fmt.Sprint("[eBPF] loadAndAssign error: ", err))
		return &Error{fmt.Errorf("[eBPF] Error loading opensnitch.o (collection): %s", err), NotAvailable}
	}
	collectionMaps = append(collectionMaps, m)

	kp, err := link.Kprobe("tcp_v4_connect", ebpfMod.KProbeTCPv4Connect, nil)
	if err != nil {
		log.Error("opening kprobe: %s", err)
	}
	hooks = append(hooks, kp)
	kp, err = link.Kretprobe("tcp_v4_connect", ebpfMod.KretProbeTCPv4Connect, nil)
	if err != nil {
		log.Error("opening kretprobe: %s", err)
	}
	hooks = append(hooks, kp)
	kp, err = link.Kprobe("tcp_v6_connect", ebpfMod.KProbeTCPv6Connect, nil)
	if err != nil {
		log.Error("opening kprobe: %s", err)
	}
	hooks = append(hooks, kp)
	kp, err = link.Kretprobe("tcp_v6_connect", ebpfMod.KretProbeTCPv6Connect, nil)
	if err != nil {
		log.Error("opening kretprobe: %s", err)
	}
	hooks = append(hooks, kp)
	kp, err = link.Kprobe("udp_sendmsg", ebpfMod.KProbeUDPv4Connect, nil)
	if err != nil {
		log.Error("opening kprobe: %s", err)
	}
	hooks = append(hooks, kp)
	kp, err = link.Kprobe("udpv6_sendmsg", ebpfMod.KProbeUDPv6Connect, nil)
	if err != nil {
		log.Error("opening kprobe: %s", err)
	}
	hooks = append(hooks, kp)
	kp, err = link.Kprobe("iptunnel_xmit", ebpfMod.KProbeIPtunnelXmit, nil)
	if err != nil {
		log.Error("opening kprobe: %s", err)
	}
	hooks = append(hooks, kp)
	kp, err = link.Kprobe("inet_dgram_connect", ebpfMod.KProbeInetDgramConnect, nil)
	if err != nil {
		log.Error("opening kprobe: %s", err)
	}
	hooks = append(hooks, kp)
	kp, err = link.Kretprobe("inet_dgram_connect", ebpfMod.KretProbeInetDgramConnect, nil)
	if err != nil {
		log.Error("opening kretprobe: %s", err)
	}
	hooks = append(hooks, kp)

	ebpfMaps = map[string]*ebpfMapsForProto{
		"tcp":  {bpfMap: ebpfMod.TCPMap},
		"udp":  {bpfMap: ebpfMod.UDPMap},
		"tcp6": {bpfMap: ebpfMod.TCPv6Map},
		"udp6": {bpfMap: ebpfMod.UDPv6Map},
	}
	for prot, mfp := range ebpfMaps {
		if mfp.bpfMap == nil {
			return &Error{fmt.Errorf("eBPF module opensnitch.o malformed, bpfmap[%s] nil", prot), NotAvailable}
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
		if sock == nil {
			continue
		}
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

	if eventsReader != nil {
		eventsReader.Close()
	}

	for _, k := range hooks {
		if k != nil {
			log.Trace("[eBPF] Stop() hook: %+v\n", k)
			k.Close()
		}
	}
	for _, k := range collectionMaps {
		if k != nil {
			log.Trace("[eBPF] Stop() map: %+v\n", k)
			k.Close()
		}
	}
	hooks = []link.Link{}
	collectionMaps = make([]*ebpf.Collection, 0)

	if m != nil {
		m.Close()
	}

}

// TODO: remove
// make bpf() syscall with bpf_lookup prepared by the caller
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
		//fmt.Printf("kernelEvents queue full (%d)", len(kernelEvents))
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
