package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
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
	Pad         uint16
	ArgsCount   uint8
	ArgsPartial uint8
	Filename    [MaxPathLen]byte
	Args        [MaxArgs][MaxArgLen]byte
	Comm        [TaskCommLen]byte
}

// Struct that holds the metadata of a connection.
// When we receive a new connection, we look for it on the eBPF maps,
// and if it's found, this information is returned.
type networkEventT struct {
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
)

// EventsProgsDefs holds the hooks defined in the module
type EventsProgsDefs struct {
	TPointExecve        *ebpf.Program `ebpf:"tracepoint__syscalls_sys_enter_execve"`
	TPointExecveAt      *ebpf.Program `ebpf:"tracepoint__syscalls_sys_enter_execveat"`
	TPointExitExecve    *ebpf.Program `ebpf:"tracepoint__syscalls_sys_exit_execve"`
	TPointExitExecveAt  *ebpf.Program `ebpf:"tracepoint__syscalls_sys_exit_execveat"`
	TPointSchedProcExit *ebpf.Program `ebpf:"tracepoint__sched_sched_process_exit"`
	//TPointSchedProcExec *ebpf.Program `ebpf:"tracepoint__sched_sched_process_exec"`
	//TPointBind *ebpf.Program `ebpf:"tracepoint__syscalls_sys_enter_bind"`
	//TPointBindExit *ebpf.Program `ebpf:"tracepoint__syscalls_sys_exit_bind"`
}

// EventsMapsDefs holds the maps defined in the module
type EventsMapsDefs struct {
	// BPF_MAP_TYPE_PERF_EVENT_ARRAY
	PerfEvents *ebpf.Map `ebpf:"events"`
}

// container of hooks and maps
type eventsDefsT struct {
	EventsProgsDefs
	EventsMapsDefs
}

func initEventsStreamer() *Error {
	eventsColl, err := core.LoadEbpfModule("opensnitch-procs.o", ebpfCfg.ModulesPath)
	if err != nil {
		dispatchErrorEvent(fmt.Sprint("[eBPF events] collections: ", err))
		return &Error{err, EventsNotAvailable}
	}

	ebpfMod := eventsDefsT{}
	if err := eventsColl.Assign(&ebpfMod); err != nil {
		dispatchErrorEvent(fmt.Sprint("[eBPF events] assign: ", err))
		return &Error{err, EventsNotAvailable}
	}
	collectionMaps = append(collectionMaps, eventsColl)

	// User space needs to perf_event_open() it (...) before eBPF program can send data into it.
	if err := initPerfMap(ebpfMod.PerfEvents); err != nil {
		dispatchErrorEvent(fmt.Sprint("[eBPF events] perfMap: ", err))
		return &Error{err, EventsNotAvailable}
	}

	failed_tps := ""
	tp1, err := link.Tracepoint("syscalls", "sys_enter_execve", ebpfMod.TPointExecve, nil)
	if err != nil {
		failed_tps = "sys_enter_execve"
		log.Error("[eBPF events] sys_enter_execve: %s", err)
	}
	hooks = append(hooks, tp1)
	tp2, err := link.Tracepoint("syscalls", "sys_exit_execve", ebpfMod.TPointExitExecve, nil)
	if err != nil {
		failed_tps += " sys_exit_execve"
		log.Error("[eBPF events] sys_exit_execve: %s", err)
	}
	hooks = append(hooks, tp2)
	tp3, err := link.Tracepoint("syscalls", "sys_enter_execveat", ebpfMod.TPointExecveAt, nil)
	if err != nil {
		failed_tps += " sys_enter_execveat"
		log.Error("[eBPF events] sys_enter_execveat: %s", err)
	}
	hooks = append(hooks, tp3)
	tp4, err := link.Tracepoint("syscalls", "sys_exit_execveat", ebpfMod.TPointExitExecveAt, nil)
	if err != nil {
		failed_tps += " sys_exit_execveat"
		log.Error("[eBPF events] sys_exit_execveat: %s", err)
	}
	hooks = append(hooks, tp4)
	tpe, err := link.Tracepoint("sched", "sched_process_exit", ebpfMod.TPointSchedProcExit, nil)
	if err != nil {
		failed_tps += " sched_process_exit"
		log.Error("[eBPF events] sched_process_exit: %s", err)
	}
	hooks = append(hooks, tpe)

	if failed_tps != "" {
		dispatchErrorEvent(fmt.Sprint("[eBPF events] Some tracepoints not loaded:\n", failed_tps))
	}

	return nil
}

func initPerfMap(events *ebpf.Map) error {
	var err error
	eventsReader, err = ringbuf.NewReader(events)
	if err != nil {
		return err
	}
	perfChan := make(chan []byte, ebpfCfg.QueueEventsSize)

	for i := 0; i < ebpfCfg.EventsWorkers; i++ {
		go streamEventsWorker(i, perfChan, kernelEvents)
	}

	// TODO: check if spawning several goroutines improves performance.
	go func(perfChan chan []byte, rd *ringbuf.Reader) {
		for {
			select {
			case <-ctxTasks.Done():
				goto Exit
			default:
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						goto Exit
					}
					// XXX: control max errors?
					log.Trace("[eBPF events] reader error: %s", err)
					continue
				}
				perfChan <- record.RawSample
			}
		}
	Exit:
		log.Debug("[eBPF events] reader closed")
	}(perfChan, eventsReader)

	return nil
}

func streamEventsWorker(id int, chn chan []byte, kernelEvents chan interface{}) {
	var event execEvent
	var buf bytes.Buffer
	errors := 0
	maxErrors := 20 // we should have no errors.
	tooManyErrors := func() bool {
		errors++
		if errors > maxErrors {
			log.Error("[eBPF events] too many errors parsing events from kernel")
			log.Error("verify that you're using the correct eBPF modules for this version (%s)", core.Version)
			return true
		}
		return false
	}

	for incomingEvent := range chn {
		event = execEvent{}
		buf.Reset()

		select {
		case <-ctxTasks.Done():
			goto Exit
		default:
		}

		buf.Write(incomingEvent)
		if err := binary.Read(&buf, hostByteOrder, &event); err != nil {
			if tooManyErrors() {
				goto Exit
			}
			log.Debug("[eBPF events #%d] error: %s", id, err)
			continue
		}

		switch event.Type {
		case EV_TYPE_EXEC, EV_TYPE_EXECVEAT:
			processExecEvent(&event)

		case EV_TYPE_SCHED_EXIT:
			processExitEvent(&event)

		}
	}

Exit:
	log.Debug("perfMap goroutine exited #%d", id)
}

// processExecEvent parses an execEvent to Process, saves or reuses it to
// cache, and decides if it needs to be updated.
func processExecEvent(event *execEvent) {
	proc := event2process(event)
	if proc == nil {
		return
	}
	log.Debug("[eBPF exec event] type: %d, ppid: %d, pid: %d, uid: %d, %s -> %s", event.Type, event.PPID, event.PID, event.UID, proc.Path, proc.Args)
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
	log.Debug("[eBPF event inCache] pid: %d, uid: %d, %s", event.PID, event.UID, item.Proc.Path)
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
}
