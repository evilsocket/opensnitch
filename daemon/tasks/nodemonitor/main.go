package nodemonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks"
)

// Name of this task
var Name = "node-monitor"

// Config of this task
type Config struct {
	Interval string
	Name     string
}

// NodeMonitor monitors the resources of a node (ram, swap, load avg, etc).
type NodeMonitor struct {
	tasks.TaskBase
	mu     *sync.RWMutex
	Ticker *time.Ticker

	Interval string
	Node     string
}

// New returns a new NodeMonitor
func New(node, interval string, stopOnDisconnect bool) (string, *NodeMonitor) {
	return fmt.Sprint(Name, "-", node), &NodeMonitor{
		TaskBase: tasks.TaskBase{
			Results: make(chan interface{}),
			Errors:  make(chan error),
		},
		mu:       &sync.RWMutex{},
		Node:     node,
		Interval: interval,
	}
}

// Start ...
func (pm *NodeMonitor) Start(ctx context.Context, cancel context.CancelFunc) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.Ctx = ctx
	pm.Cancel = cancel

	if pm.Interval == "" {
		pm.Interval = "5s"
	}
	interval, err := time.ParseDuration(pm.Interval)
	if err != nil {
		return err
	}
	pm.Ticker = time.NewTicker(interval)
	go func(ctx context.Context) {
		var info syscall.Sysinfo_t
		for {
			select {
			case <-ctx.Done():
				goto Exit
			case <-pm.Ticker.C:
				// TODO:
				//  - filesystem stats
				//  - daemon status (mem && cpu usage, internal/debug pkg, etc)
				err := syscall.Sysinfo(&info)
				if err != nil {
					pm.TaskBase.Errors <- err
					continue
				}
				infoJSON, err := json.Marshal(info)
				if err != nil {
					pm.TaskBase.Errors <- err
					continue
				}
				pm.TaskBase.Results <- unsafe.String(unsafe.SliceData(infoJSON), len(infoJSON))
			}
		}
	Exit:
		log.Debug("[tasks.NodeMonitor] stopped (%s)", pm.Node)
	}(ctx)
	return err
}

// Pause stops temporarily the task. For example it might be paused when the
// connection with the GUI (server) is closed.
func (pm *NodeMonitor) Pause() error {
	// TODO
	return nil
}

// Resume stopped tasks.
func (pm *NodeMonitor) Resume() error {
	// TODO
	return nil
}

// Stop ...
func (pm *NodeMonitor) Stop() error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.StopOnDisconnect {
		return nil
	}
	pm.Ticker.Stop()
	pm.Cancel()
	close(pm.TaskBase.Results)
	close(pm.TaskBase.Errors)
	return nil
}

// Results ...
func (pm *NodeMonitor) Results() <-chan interface{} {
	return pm.TaskBase.Results
}

// Errors ...
func (pm *NodeMonitor) Errors() <-chan error {
	return pm.TaskBase.Errors
}
