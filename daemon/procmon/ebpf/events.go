package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"

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
	PID         uint64
	PPID        uint64
	UID         uint64
	ArgsCount   uint64
	ArgsPartial uint64
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
}

// List of supported events
const (
	EV_TYPE_NONE = iota
	EV_TYPE_EXEC
	EV_TYPE_EXECVEAT
	EV_TYPE_FORK
	EV_TYPE_SCHED_EXIT
)

var (
	execEvents       = NewEventsStore()
	stopStreamEvents = make(chan bool)
	perfMapList      = make(map[*elf.PerfMap]*elf.Module)
	// total workers spawned by the different events PerfMaps
	eventWorkers = 0
	perfMapName  = "proc-events"

	// default value is 8.
	// Not enough to handle high loads such http downloads, torent traffic, etc.
	// (regular desktop usage)
	ringBuffSize = 64 // * PAGE_SIZE (4k usually)
)

func initEventsStreamer() {
	elfOpts := make(map[string]elf.SectionParams)
	elfOpts["maps/"+perfMapName] = elf.SectionParams{PerfRingBufferPageCount: ringBuffSize}
	mp, err := core.LoadEbpfModule("opensnitch-procs.o")
	if err != nil {
		dispatchErrorEvent(fmt.Sprint("[eBPF events]: ", err))
		return
	}
	mp.EnableOptionCompatProbe()

	if err = mp.Load(elfOpts); err != nil {
		dispatchErrorEvent(fmt.Sprint("[eBPF events]: ", err))
		return
	}

	tracepoints := []string{
		"tracepoint/sched/sched_process_exit",
		"tracepoint/syscalls/sys_enter_execve",
		"tracepoint/syscalls/sys_enter_execveat",
		//"tracepoint/sched/sched_process_exec",
		//"tracepoint/sched/sched_process_fork",
	}

	// Enable tracepoints first, that way if kprobes fail loading we'll still have some
	for _, tp := range tracepoints {
		err = mp.EnableTracepoint(tp)
		if err != nil {
			dispatchErrorEvent(fmt.Sprintf("[eBPF events] error enabling tracepoint %s: %s", tp, err))
		}
	}

	if err = mp.EnableKprobes(0); err != nil {
		// if previous shutdown was unclean, then we must remove the dangling kprobe
		// and install it again (close the module and load it again)
		mp.Close()
		if err = mp.Load(elfOpts); err != nil {
			dispatchErrorEvent(fmt.Sprintf("[eBPF events] failed to load /etc/opensnitchd/opensnitch-procs.o (2): %v", err))
			return
		}
		if err = mp.EnableKprobes(0); err != nil {
			dispatchErrorEvent(fmt.Sprintf("[eBPF events] error enabling kprobes: %v", err))
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	go func(sig chan os.Signal) {
		<-sig
	}(sig)

	eventWorkers = 0
	initPerfMap(mp)
}

func initPerfMap(mod *elf.Module) {
	perfChan := make(chan []byte)
	lostEvents := make(chan uint64, 1)
	var err error
	perfMap, err := elf.InitPerfMap(mod, perfMapName, perfChan, lostEvents)
	if err != nil {
		dispatchErrorEvent(fmt.Sprintf("[eBPF events] Error initializing eBPF events perfMap: %s", err))
		return
	}
	perfMapList[perfMap] = mod

	eventWorkers += 4
	for i := 0; i < eventWorkers; i++ {
		go streamEventsWorker(i, perfChan, lostEvents, kernelEvents, execEvents)
	}
	perfMap.PollStart()
}

// FIXME: under heavy load these events may arrive AFTER network events
func streamEventsWorker(id int, chn chan []byte, lost chan uint64, kernelEvents chan interface{}, execEvents *eventsStore) {
	var event execEvent
	for {
		select {
		case <-stopStreamEvents:
			goto Exit
		case l := <-lost:
			log.Debug("Lost ebpf events: %d", l)
		case d := <-chn:
			if err := binary.Read(bytes.NewBuffer(d), hostByteOrder, &event); err != nil {
				log.Error("[eBPF events #%d] error: %s", id, err)
			} else {
				switch event.Type {
				case EV_TYPE_EXEC, EV_TYPE_EXECVEAT:
					if _, found := execEvents.isInStore(event.PID); found {
						log.Debug("[eBPF event inCache] -> %d", event.PID)
						continue
					}
					proc := event2process(&event)
					if proc == nil {
						continue
					}
					execEvents.add(event.PID, event, *proc)

				case EV_TYPE_SCHED_EXIT:
					log.Debug("[eBPF exit event] -> %d", event.PID)
					if _, found := execEvents.isInStore(event.PID); found {
						log.Debug("[eBPF exit event inCache] -> %d", event.PID)
						execEvents.delete(event.PID)
					}
				}
				// TODO: delete old events (by timeout)
			}
		}
	}

Exit:
	log.Debug("perfMap goroutine exited #%d", id)
}

func event2process(event *execEvent) (proc *procmon.Process) {

	proc = procmon.NewProcess(int(event.PID), byteArrayToString(event.Comm[:]))
	// trust process path received from kernel
	path := byteArrayToString(event.Filename[:])
	if path != "" {
		proc.SetPath(path)
	} else {
		if proc.ReadPath() != nil {
			return nil
		}
	}
	proc.ReadCwd()
	proc.ReadEnv()
	proc.UID = int(event.UID)

	if event.ArgsPartial == 0 {
		for i := 0; i < int(event.ArgsCount); i++ {
			proc.Args = append(proc.Args, byteArrayToString(event.Args[i][:]))
		}
		proc.CleanArgs()
	} else {
		proc.ReadCmdline()
	}
	log.Debug("[eBPF exec event] ppid: %d, pid: %d, %s -> %s", event.PPID, event.PID, proc.Path, proc.Args)

	return
}
