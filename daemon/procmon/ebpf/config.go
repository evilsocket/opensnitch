package ebpf

import "github.com/evilsocket/opensnitch/daemon/log"

// Config holds the configuration to customize ebpf module behaviour.
type Config struct {
	ModulesPath string `json:"ModulesPath"`

	// system default value is 8, but it's not enough to handle "high" loads such
	// http downloads, torrent traffic, etc. (just regular desktop usage)
	// We set it to 64 by default (* PAGE_SIZE, which is usually 4a).
	RingBuffSize int `json:"RingBuffSize"`

	// number of workers to handle events from kernel
	EventsWorkers int `json:"EventsWorkers"`

	// max number of events in the queue received from the kernel.
	// 0 - Default behaviour. Each goroutine will wait for incoming messages, to
	//     dispatch them one at a time.
	// > 0 - same as above, but if the daemon is not fast enough to dispatch the
	// events, they'll be queued. Once the daemon queue is full, kernel ebpf program
	// will have to wait/discard new events. (XXX: citation/testing needed).
	QueueEventsSize int `json:"QueueEventsSize"`
}

func setConfig(ebpfOpts Config) {
	ebpfCfg = ebpfOpts

	// ModulesPath defined in core.ebpf
	// QueueEventsSize defaults to 0

	if ebpfCfg.EventsWorkers == 0 {
		ebpfCfg.EventsWorkers = 8
	}

	if ebpfCfg.RingBuffSize == 0 {
		ebpfCfg.RingBuffSize = 64
	}

	log.Debug("[eBPF] config loaded: %v", ebpfCfg)
}
