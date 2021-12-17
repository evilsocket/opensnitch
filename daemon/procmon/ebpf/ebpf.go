package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	elf "github.com/iovisor/gobpf/elf"
)

//contains pointers to ebpf maps for a given protocol (tcp/udp/v6)
type ebpfMapsForProto struct {
	counterMap *elf.Map
	bpfmap     *elf.Map
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

var (
	m        *elf.Module
	lock     = sync.RWMutex{}
	mapSize  = uint(12000)
	ebpfMaps map[string]*ebpfMapsForProto
	//connections which were established at the time when opensnitch started
	alreadyEstablished = alreadyEstablishedConns{
		TCP:   make(map[*daemonNetlink.Socket]int),
		TCPv6: make(map[*daemonNetlink.Socket]int),
	}

	//stop == true is a signal for all goroutines to stop
	stop = false

	// list of local addresses of this machine
	localAddresses []net.IP

	hostByteOrder binary.ByteOrder
)

//Start installs ebpf kprobes
func Start() error {
	m = elf.NewModule("/etc/opensnitchd/opensnitch.o")
	if err := m.Load(nil); err != nil {
		log.Error("eBPF Failed to load /etc/opensnitchd/opensnitch.o: %v", err)
		return err
	}

	// if previous shutdown was unclean, then we must remove the dangling kprobe
	// and install it again (close the module and load it again)
	if err := m.EnableKprobes(0); err != nil {
		m.Close()
		if err := m.Load(nil); err != nil {
			log.Error("eBPF failed to load /etc/opensnitchd/opensnitch.o (2): %v", err)
			return err
		}
		if err := m.EnableKprobes(0); err != nil {
			log.Error("eBPF error when enabling kprobes: %v", err)
			return err
		}
	}

	// init all connection counters to 0
	zeroKey := make([]byte, 4)
	zeroValue := make([]byte, 8)
	for _, name := range []string{"tcpcounter", "tcpv6counter", "udpcounter", "udpv6counter"} {
		err := m.UpdateElement(m.Map(name), unsafe.Pointer(&zeroKey[0]), unsafe.Pointer(&zeroValue[0]), 0)
		if err != nil {
			log.Error("eBPF could not init counters to zero: %v", err)
			return err
		}
	}
	ebpfCache = NewEbpfCache()

	lock.Lock()
	//determine host byte order
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		hostByteOrder = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		hostByteOrder = binary.BigEndian
	default:
		log.Error("Could not determine host byte order.")
	}
	lock.Unlock()

	ebpfMaps = map[string]*ebpfMapsForProto{
		"tcp": {
			counterMap: m.Map("tcpcounter"),
			bpfmap:     m.Map("tcpMap")},
		"tcp6": {
			counterMap: m.Map("tcpv6counter"),
			bpfmap:     m.Map("tcpv6Map")},
		"udp": {
			counterMap: m.Map("udpcounter"),
			bpfmap:     m.Map("udpMap")},
		"udp6": {
			counterMap: m.Map("udpv6counter"),
			bpfmap:     m.Map("udpv6Map")},
	}

	saveEstablishedConnections(uint8(syscall.AF_INET))
	if core.IPv6Enabled {
		saveEstablishedConnections(uint8(syscall.AF_INET6))
	}

	go monitorCache()
	go monitorMaps()
	go monitorLocalAddresses()
	go monitorAlreadyEstablished()
	return nil
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

// Stop stops monitoring connections using kprobes
func Stop() {
	lock.Lock()
	stop = true
	lock.Unlock()
	if m != nil {
		m.Close()
	}
	ebpfCache.clear()
}

func isStopped() bool {
	lock.RLock()
	defer lock.RUnlock()

	return stop
}

//make bpf() syscall with bpf_lookup prepared by the caller
func makeBpfSyscall(bpf_lookup *bpf_lookup_elem_t) uintptr {
	BPF_MAP_LOOKUP_ELEM := 1 //cmd number
	syscall_BPF := 321       //syscall number
	sizeOfStruct := 24       //sizeof bpf_lookup_elem_t struct

	r1, _, _ := syscall.Syscall(uintptr(syscall_BPF), uintptr(BPF_MAP_LOOKUP_ELEM),
		uintptr(unsafe.Pointer(bpf_lookup)), uintptr(sizeOfStruct))
	return r1
}
