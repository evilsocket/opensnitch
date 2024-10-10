package pidmonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/tasks"
)

// Name s the base name of this task.
// When adding a new task, it'll be created as "pid-monitor-" + <pid>
var Name = "pid-monitor"

// Config of this task
type Config struct {
	Interval string
	Pid      int
}

// PIDMonitor monitors a process ID.
type PIDMonitor struct {
	tasks.TaskBase
	mu        *sync.RWMutex
	Ticker    *time.Ticker
	Interval  string
	Pid       int
	isStopped bool
}

// New returns a new PIDMonitor
func New(pid int, interval string, stopOnDisconnect bool) (string, *PIDMonitor) {
	return fmt.Sprint(Name, "-", pid), &PIDMonitor{
		TaskBase: tasks.TaskBase{
			Results: make(chan interface{}),
			Errors:  make(chan error),
		},
		mu:       &sync.RWMutex{},
		Pid:      pid,
		Interval: interval,
	}
}

// Start ...
func (pm *PIDMonitor) Start(ctx context.Context, cancel context.CancelFunc) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pm.Ctx = ctx
	pm.Cancel = cancel
	p := &procmon.Process{}
	item, found := procmon.EventsCache.IsInStoreByPID(pm.Pid)
	if found {
		newProc := item.Proc
		p = &newProc
		if len(p.Tree) == 0 {
			p.GetParent()
			p.BuildTree()
		}
	} else {
		p = procmon.NewProcess(pm.Pid, "")
	}

	if pm.Interval == "" {
		pm.Interval = "5s"
	}
	interval, err := time.ParseDuration(pm.Interval)
	if err != nil {
		return err
	}
	pm.Ticker = time.NewTicker(interval)
	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				goto Exit
			case <-pm.Ticker.C:
				// TODO: errors counter, and exit on errors > X
				if err := p.GetExtraInfo(); err != nil {
					pm.TaskBase.Errors <- err
					goto Exit
				}
				pJSON, err := json.Marshal(p)
				if err != nil {
					pm.TaskBase.Errors <- err
					continue
				}
				if pm.isStopped {
					goto Exit
				}
				// ~200µs (string()) vs ~60ns
				pm.TaskBase.Results <- unsafe.String(unsafe.SliceData(pJSON), len(pJSON))
			}
		}
	Exit:
		log.Debug("[tasks.PIDMonitor] stopped (%d)", pm.Pid)
	}(ctx)
	return err
}

// Pause stops temporarily the task. For example it might be paused when the
// connection with the GUI (server) is closed.
func (pm *PIDMonitor) Pause() error {
	// TODO
	return nil
}

// Resume stopped tasks.
func (pm *PIDMonitor) Resume() error {
	// TODO
	return nil
}

// Stop ...
func (pm *PIDMonitor) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.StopOnDisconnect {
		log.Debug("[task.PIDMonitor] ignoring Stop()")
		return nil
	}
	pm.isStopped = true

	log.Debug("[task.PIDMonitor] Stop()")
	pm.Ticker.Stop()
	pm.Cancel()
	close(pm.TaskBase.Results)
	close(pm.TaskBase.Errors)
	return nil
}

// Results ...
func (pm *PIDMonitor) Results() <-chan interface{} {
	return pm.TaskBase.Results
}

// Errors ...
func (pm *PIDMonitor) Errors() <-chan error {
	return pm.TaskBase.Errors
}
