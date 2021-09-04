package procmon

import (
	"io/ioutil"
	"strconv"
	"sync"

	"github.com/evilsocket/ftrace"
	"github.com/evilsocket/opensnitch/daemon/log"
)

const (
	probeName   = "opensnitch_exec_probe"
	syscallName = "do_execve"
)

type procData struct {
	path string
	args []string
}

var (
	subEvents = []string{
		"sched/sched_process_fork",
		"sched/sched_process_exec",
		"sched/sched_process_exit",
	}

	watcher       = ftrace.NewProbe(probeName, syscallName, subEvents)
	isAvailable   = false
	monitorMethod = MethodProc

	index = make(map[int]*procData)
	lock  = sync.RWMutex{}
)

func forEachProcess(cb func(pid int, path string, args []string) bool) {
	lock.RLock()
	defer lock.RUnlock()

	for pid, data := range index {
		if cb(pid, data.path, data.args) == true {
			break
		}
	}
}

func trackProcess(pid int) {
	lock.Lock()
	defer lock.Unlock()
	if _, found := index[pid]; found == false {
		index[pid] = &procData{}
	}
}

func trackProcessArgs(e ftrace.Event) {
	lock.Lock()
	defer lock.Unlock()

	if d, found := index[e.PID]; found == false {
		index[e.PID] = &procData{
			args: e.Argv(),
			path: "",
		}
	} else {
		d.args = e.Argv()
	}
}

func trackProcessPath(e ftrace.Event) {
	lock.Lock()
	defer lock.Unlock()
	if d, found := index[e.PID]; found == false {
		index[e.PID] = &procData{
			path: e.Args["filename"],
		}
	} else {
		d.path = e.Args["filename"]
	}
}

func trackProcessExit(e ftrace.Event) {
	lock.Lock()
	defer lock.Unlock()
	delete(index, e.PID)
}

func eventConsumer() {
	for event := range watcher.Events() {
		if event.IsSyscall == true {
			trackProcessArgs(event)
		} else if _, ok := event.Args["filename"]; ok && event.Name == "sched_process_exec" {
			trackProcessPath(event)
		} else if event.Name == "sched_process_exit" {
			trackProcessExit(event)
		}
	}
}

// Start enables the ftrace monitor method.
// This method configures a kprobe to intercept execve() syscalls.
// The kernel must have configured and enabled debugfs.
func Start() (err error) {
	// start from a clean state
	if err := watcher.Reset(); err != nil && watcher.Enabled() {
		log.Warning("ftrace.Reset() error: %v", err)
	}

	if err = watcher.Enable(); err == nil {
		isAvailable = true

		go eventConsumer()
		// track running processes
		if ls, err := ioutil.ReadDir("/proc/"); err == nil {
			for _, f := range ls {
				if pid, err := strconv.Atoi(f.Name()); err == nil && f.IsDir() {
					trackProcess(pid)
				}
			}
		}
	} else {
		isAvailable = false
	}
	return
}

// Stop disables ftrace monitor method, removing configured kprobe.
func Stop() error {
	isAvailable = false
	return watcher.Disable()
}

// IsWatcherAvailable checks if ftrace (debugfs) is
func IsWatcherAvailable() bool {
	return isAvailable
}
