package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	elf "github.com/iovisor/gobpf/elf"
)

// MaxPathLen defines the maximum length of a path, as defined by the kernel:
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/limits.h#L13
const MaxPathLen = 4096

// MaxArgs defines the maximum number of arguments allowed
const MaxArgs = 20

// MaxArgLen defines the maximum length of each argument.
// NOTE: this value is 131072 (PAGE_SIZE * 32)
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/binfmts.h#L16
const MaxArgLen = 256

// TaskCommLen is the maximum num of characters of the comm field
const TaskCommLen = 16

type execEvent struct {
	Type        uint64
	PID         uint32
	UID         uint32
	PPID        uint32
	RetCode     uint32
	ArgsCount   uint8
	ArgsPartial uint8
	Filename    [MaxPathLen]byte
	Args        [MaxArgs][MaxArgLen]byte
	Comm        [TaskCommLen]byte
	Pad1        uint16
	Pad2        uint32
}

type netEventT struct {
	Type      uint64
	SaddrV6   uint64
	DaddrV6   uint64
	Cookie    uint64
	BytesSent uint64
	BytesRecv uint64
	LastSeen  uint64
	PID       uint32
	UID       uint32
	PPID      uint32
	Proto     uint32

	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Fam   uint8
}

// Struct that holds the metadata of a connection.
// When we receive a new connection via nfqueue, we look for it on the
// eBPF maps by the key srcport+srcip+dstip+dstport.
// If it's found, the following struct/info is returned (defined in opensnitch.c).
type connEventT struct {
	Pid  uint64
	UID  uint64
	Comm [TaskCommLen]byte
	//Ns   uint64
}

// List of supported events
const (
	EV_TYPE_NONE = iota
	EV_TYPE_EXEC
	EV_TYPE_EXECVEAT
	EV_TYPE_FORK
	EV_TYPE_SCHED_EXIT
	EV_TYPE_TCP_CONN_DESTROYED
	EV_TYPE_UDP_CONN_DESTROYED
	EV_TYPE_RECV_BYTES
	EV_TYPE_SENT_BYTES
)

var (
	perfMapList = make(map[*elf.PerfMap]*elf.Module)
	// total workers spawned by the different events PerfMaps
	eventWorkers = 0
	perfMapName  = "proc-events"

	// default value is 8.
	// Not enough to handle "high loads" such http downloads, torrent traffic, etc.
	// (regular desktop usage)
	ringBuffSize = 64 // * PAGE_SIZE (4k usually)
)

func initEventsStreamer() *Error {
	elfOpts := make(map[string]elf.SectionParams)
	elfOpts["maps/"+perfMapName] = elf.SectionParams{PerfRingBufferPageCount: ringBuffSize}
	var err error
	perfMod, err = core.LoadEbpfModule("opensnitch-procs.o", modulesPath)
	if err != nil {
		dispatchErrorEvent(fmt.Sprint("[eBPF events]: ", err))
		return &Error{err, EventsNotAvailable}
	}
	perfMod.EnableOptionCompatProbe()

	if err = perfMod.Load(elfOpts); err != nil {
		dispatchErrorEvent(fmt.Sprint("[eBPF events]: ", err))
		return &Error{err, EventsNotAvailable}
	}

	tracepoints := []string{
		"tracepoint/sched/sched_process_exit",
		"tracepoint/syscalls/sys_enter_execve",
		"tracepoint/syscalls/sys_enter_execveat",
		"tracepoint/syscalls/sys_exit_execve",
		"tracepoint/syscalls/sys_exit_execveat",
		//"tracepoint/sched/sched_process_exec",
		//"tracepoint/sched/sched_process_fork",
	}

	// Enable tracepoints first, that way if kprobes fail loading we'll still have some
	for _, tp := range tracepoints {
		err = perfMod.EnableTracepoint(tp)
		if err != nil {
			dispatchErrorEvent(fmt.Sprintf(`[eBPF events] error enabling tracepoint %s: %s
Verify that your kernel has support for tracepoints (opensnitchd -check-requirements).`, tp, err))
		}
	}

	if err = perfMod.EnableKprobes(0); err != nil {
		// if previous shutdown was unclean, then we must remove the dangling kprobe
		// and install it again (close the module and load it again)
		perfMod.Close()
		if err = perfMod.Load(elfOpts); err != nil {
			dispatchErrorEvent(fmt.Sprintf("[eBPF events] failed to load /etc/opensnitchd/opensnitch-procs.o (2): %v", err))
			return &Error{err, EventsNotAvailable}
		}
		if err = perfMod.EnableKprobes(0); err != nil {
			dispatchErrorEvent(fmt.Sprintf("[eBPF events] error enabling kprobes: %v", err))
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	go func(sig chan os.Signal) {
		<-sig
	}(sig)

	eventWorkers = 0
	if err := initPerfMap(perfMod); err != nil {
		return &Error{err, EventsNotAvailable}
	}

	return nil
}

func initPerfMap(mod *elf.Module) error {
	perfChan := make(chan []byte)
	lostEvents := make(chan uint64, 1)
	var err error
	perfMap, err := elf.InitPerfMap(mod, perfMapName, perfChan, lostEvents)
	if err != nil {
		dispatchErrorEvent(fmt.Sprintf("[eBPF events] Error initializing eBPF events perfMap: %s", err))
		return err
	}
	perfMapList[perfMap] = mod

	eventWorkers += 8
	for i := 0; i < eventWorkers; i++ {
		go streamEventsWorker(i, perfChan, lostEvents, kernelEvents)
	}
	perfMap.PollStart()

	return nil
}

func streamEventsWorker(id int, chn chan []byte, lost chan uint64, kernelEvents chan interface{}) {
	var event execEvent
	var netEvent netEventT
	var buf bytes.Buffer

	for {
		event = execEvent{}
		netEvent = netEventT{}
		buf.Reset()

		select {
		case <-ctxTasks.Done():
			goto Exit
		case l := <-lost:
			log.Debug("Lost ebpf events: %d", l)
		case incomingEvent := <-chn:
			switch incomingEvent[0] {
			case EV_TYPE_SENT_BYTES,
				EV_TYPE_RECV_BYTES,
				EV_TYPE_TCP_CONN_DESTROYED,
				EV_TYPE_UDP_CONN_DESTROYED:

				buf.Write(incomingEvent)
				if err := binary.Read(&buf, hostByteOrder, &netEvent); err != nil {
					log.Debug("[eBPF NET events #%d] netbytes error: %s", id, err)
					continue
				}
			default:
				buf.Write(incomingEvent)
				if err := binary.Read(&buf, hostByteOrder, &event); err != nil {
					log.Debug("[eBPF events #%d] error: %s, event: %d", id, err, incomingEvent[0])
					continue
				}
			}

			switch incomingEvent[0] {
			case EV_TYPE_SENT_BYTES, EV_TYPE_RECV_BYTES:
				//dstIP := make(net.IP, 4)
				//srcIP := make(net.IP, 4)
				//binary.BigEndian.PutUint32(srcIP, netEvent.Saddr)
				log.Debug("[eBPF events recv/sent]: %d, pid: %d, proto: %d sport: %d -> dport: %d, bytes_sent: %d, bytes_recv: %d", netEvent.Type, netEvent.PID, netEvent.Proto, netEvent.Sport, netEvent.Dport, netEvent.BytesSent, netEvent.BytesRecv)
				item, found := procmon.EventsCache.IsInStoreByPID(int(netEvent.PID))
				if found {
					dispatchRxTxEvent(&item.Proc, netEvent.Proto, netEvent.Fam, netEvent.BytesSent, netEvent.BytesRecv)
					// TODO: Proc.AddBytes? to apply quotas more rapidly?
					procmon.EventsCache.UpdateItem(&item.Proc)
					continue
				}

			case EV_TYPE_TCP_CONN_DESTROYED, EV_TYPE_UDP_CONN_DESTROYED:
				log.Debug("[eBPF events conn destroyed]: %d, pid: %d, proto: %d sport: %d -> dport: %d, bytes_sent: %d, bytes_recv: %d", netEvent.Type, netEvent.PID, netEvent.Proto, netEvent.Sport, netEvent.Dport, netEvent.BytesSent, netEvent.BytesRecv)
				item, found := procmon.EventsCache.IsInStoreByPID(int(netEvent.PID))
				if found {
					dispatchRxTxEvent(&item.Proc, netEvent.Proto, netEvent.Fam, netEvent.BytesSent, netEvent.BytesRecv)
					item.Proc.AddBytes(netEvent.Fam, netEvent.Proto, netEvent.BytesSent, netEvent.BytesRecv)
					procmon.EventsCache.UpdateItem(&item.Proc)

					continue
				}

			case EV_TYPE_EXEC, EV_TYPE_EXECVEAT:
				processExecEvent(&event)

			case EV_TYPE_SCHED_EXIT:
				processExitEvent(&event)
			}

		}
	}

Exit:
	log.Debug("perfMap goroutine exited #%d", id)
}

// processExecEvent parses an execEevent to Process, saves or reuses it to
// cache, and decides if it needs to be updated.
func processExecEvent(event *execEvent) {
	proc := event2process(event)
	if proc == nil {
		return
	}
	log.Debug("[eBPF exec event] type: %d, ppid: %d, pid: %d, %s -> %s", event.Type, event.PPID, event.PID, proc.Path, proc.Args)
	itemParent, pfound := procmon.EventsCache.IsInStoreByPID(proc.PPID)
	if pfound {
		proc.Parent = &itemParent.Proc
		proc.Tree = itemParent.Proc.Tree
	}

	item, needsUpdate, found := procmon.EventsCache.IsInStore(int(event.PID), proc)
	if !found {
		procmon.EventsCache.Add(proc)
		getProcDetails(event, proc)
		procmon.EventsCache.UpdateItem(proc)
		return
	}

	if found && needsUpdate {
		procmon.EventsCache.Update(&item.Proc, proc)
	}

	// from now on use cached Process
	log.Debug("[eBPF event inCache] -> %d, %s", event.PID, item.Proc.Path)
}

// event2process creates a new Process from execEvent
func event2process(event *execEvent) (proc *procmon.Process) {
	proc = procmon.NewProcessEmpty(int(event.PID), byteArrayToString(event.Comm[:]))
	proc.UID = int(event.UID)

	// NOTE: this is the absolute path executed, but no the real path to the binary.
	// if it's executed from a chroot, the absolute path will be /chroot/path/usr/bin/blabla
	// if it's from a container, the real absolute path will be /proc/<pid>/root/usr/bin/blabla
	path := byteArrayToString(event.Filename[:])
	if path != "" {
		proc.SetPath(path)
	} else {
		if proc.ReadPath() != nil {
			return nil
		}
	}
	if event.PPID != 0 {
		proc.PPID = int(event.PPID)
	} else {
		proc.ReadPPID()
	}

	if event.ArgsPartial == 0 {
		for i := 0; i < int(event.ArgsCount); i++ {
			proc.Args = append(proc.Args, byteArrayToString(event.Args[i][:]))
		}
		proc.CleanArgs()
	} else {
		proc.ReadCmdline()
	}

	return
}

func getProcDetails(event *execEvent, proc *procmon.Process) {
	proc.GetParent()
	proc.BuildTree()
	proc.ReadCwd()
	proc.ReadEnv()
}

func processExitEvent(event *execEvent) {
	log.Debug("[eBPF exit event] pid: %d, ppid: %d", event.PID, event.PPID)
	procmon.EventsCache.Delete(int(event.PID))

	m.DeleteElement(perfMod.Map("tcpBytesMap"), unsafe.Pointer(&event.PID))
	m.DeleteElement(perfMod.Map("udpBytesMap"), unsafe.Pointer(&event.PID))
}
