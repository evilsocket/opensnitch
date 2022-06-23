package ebpf

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/signal"

	"github.com/evilsocket/opensnitch/daemon/log"
	elf "github.com/iovisor/gobpf/elf"
)

type execEvent struct {
	Type     uint64
	PID      uint64
	PPID     uint64
	UID      uint64
	Filename [128]byte
	Comm     [16]byte
}

// Struct that holds the metadata of a connection.
// When we receive a new connection, we look for it on the eBPF maps,
// and if it's found, this information is returned.
type networkEventT struct {
	Pid     uint64
	UID     uint64
	Counter uint64
	Comm    [16]byte
}

// List of supported events
const (
	EV_TYPE_NONE = iota
	EV_TYPE_EXEC
	EV_TYPE_FORK
	EV_TYPE_SCHED_EXEC
	EV_TYPE_SCHED_EXIT
)

var (
	execEvents       = NewEventsStore()
	stopStreamEvents = make(chan bool)
	perfMapList      = make(map[*elf.PerfMap]*elf.Module)
	// total workers spawned by the different events PerfMaps
	eventWorkers = 0
)

func initEventsStreamer() {
	mp := elf.NewModule("/etc/opensnitchd/opensnitch-procs.o")
	mp.EnableOptionCompatProbe()

	if err := mp.Load(nil); err != nil {
		log.Error("[eBPF events] Failed loading /etc/opensnitchd/opensnitch-procs.o: %v", err)
		return
	}

	tracepoints := []string{
		"tracepoint/sched/sched_process_exit",
		//		"tracepoint/sched/sched_process_exec",
		//		"tracepoint/sched/sched_process_fork",
	}

	// Enable tracepoints first, that way if kprobes fail loading we'll still have some
	var err error
	for _, tp := range tracepoints {
		err = mp.EnableTracepoint(tp)
		if err != nil {
			log.Error("[eBPF events] error enabling tracepoint %s: %s", tp, err)
		}
	}

	if err = mp.EnableKprobes(0); err != nil {
		// if previous shutdown was unclean, then we must remove the dangling kprobe
		// and install it again (close the module and load it again)
		mp.Close()
		if err = mp.Load(nil); err != nil {
			log.Error("[eBPF events] failed to load /etc/opensnitchd/opensnitch-procs.o (2): %v", err)
			return
		}
		if err = mp.EnableKprobes(0); err != nil {
			log.Error("[eBPF events] error enabling kprobes: %v", err)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	go func(sig chan os.Signal) {
		<-sig
	}(sig)

	initPerfMap(mp)
}

func initPerfMap(mod *elf.Module) {
	channel := make(chan []byte)
	var err error
	perfMap, err := elf.InitPerfMap(mod, "proc-events", channel, nil)
	if err != nil {
		log.Error("initializing eBPF events perfMap: %s", err)
		return
	}
	perfMapList[perfMap] = mod

	eventWorkers += 4
	for i := 0; i < 4; i++ {
		go streamEventsWorker(i, channel, execEvents)
	}
	perfMap.PollStart()
}

// FIXME: under heavy load these events may arrive AFTER network events
func streamEventsWorker(id int, chn chan []byte, execEvents *eventsStore) {
	var event execEvent
	for {
		select {
		case <-stopStreamEvents:
			goto Exit
		case d := <-chn:
			if err := binary.Read(bytes.NewBuffer(d), hostByteOrder, &event); err != nil {
				log.Error("[eBPF events #%d] error: %s", id, err)
			} else {
				switch event.Type {
				case EV_TYPE_EXEC:
					if _, found := execEvents.isInStore(event.PID); found {
						continue
					}
					//log.Warning("::: EXEC EVENT -> READ_CMD_LINE ppid: %d, pid: %d, %s -> %s", event.PPID, event.PID, proc.Path, proc.Args)
					execEvents.add(event.PID, event)

				case EV_TYPE_SCHED_EXIT:
					//log.Warning("::: EXIT EVENT -> %d", event.PID)
					execEvents.delete(event.PID)
					continue
				}
				// TODO: delete old events (by timeout)
			}
		}
	}

Exit:
	log.Debug("perfMap goroutine exited #%d", id)
}
