package socketsmonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks"
)

// Name of this task
var Name = "sockets-monitor"

// Config of this task
// {"interval": "5s", "states": "0,1,2,3", "family": 2, "proto": 17}
type monConfig struct {
	Interval string
	State    uint8
	Proto    uint8
	Family   uint8
}

// SocketsMonitor monitors a process ID.
type SocketsMonitor struct {
	tasks.TaskBase
	mu     *sync.RWMutex
	Ticker *time.Ticker

	Config *monConfig
	states uint8

	// stop the task if the daemon is disconnected from the GUI (server)
	StopOnDisconnect bool

	// flag to indicate that the task has been stopped, so any running task should
	// exit on finish, to avoid sending data to closed channels.
	isStopped bool
}

// initConfig parses the received configuration, and initializes it if
// it's not complete.
func initConfig(config interface{}) (*monConfig, error) {
	// https://pkg.go.dev/encoding/json#Unmarshal
	// JSON objects (are converted) to map[string]interface{}
	cfg, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("[sockmon] invalid config received: %v", config)
	}
	var newCfg monConfig
	newCfg.Interval = cfg["interval"].(string)
	newCfg.State = uint8(cfg["state"].(float64))
	newCfg.Proto = uint8(cfg["proto"].(float64))
	newCfg.Family = uint8(cfg["family"].(float64))

	if newCfg.Interval == "" {
		newCfg.Interval = "5s"
	}

	return &newCfg, nil
}

// New returns a new SocketsMonitor
func New(config interface{}, stopOnDisconnect bool) (*SocketsMonitor, error) {
	cfg, err := initConfig(config)
	if err != nil {
		return nil, err
	}
	return &SocketsMonitor{
		TaskBase: tasks.TaskBase{
			Results: make(chan interface{}),
			Errors:  make(chan error),
		},
		mu:               &sync.RWMutex{},
		StopOnDisconnect: stopOnDisconnect,
		Config:           cfg,
	}, nil
}

// Start ...
func (pm *SocketsMonitor) Start(ctx context.Context, cancel context.CancelFunc) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.Ctx = ctx
	pm.Cancel = cancel

	interval, err := time.ParseDuration(pm.Config.Interval)
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
				// FIXME: ensure that dumpSockets() are not overlapped
				socketList := pm.dumpSockets()
				sockJSON, err := json.Marshal(socketList)
				if err != nil {
					if !pm.isStopped {
						pm.TaskBase.Errors <- err
					}
					goto Exit
				}
				if pm.isStopped {
					goto Exit
				}

				pm.TaskBase.Results <- unsafe.String(unsafe.SliceData(sockJSON), len(sockJSON))
			}
		}
	Exit:
		log.Debug("[tasks.SocketsMonitor] stopped")
	}(ctx)
	return err
}

// Pause stops temporarily the task. For example it might be paused when the
// connection with the GUI (server) is closed.
func (pm *SocketsMonitor) Pause() error {
	// TODO
	return nil
}

// Resume stopped tasks.
func (pm *SocketsMonitor) Resume() error {
	// TODO
	return nil
}

// Stop ...
func (pm *SocketsMonitor) Stop() error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.StopOnDisconnect {
		return nil
	}
	log.Debug("[task.SocketsMonitor] Stop()")
	pm.isStopped = true
	pm.Ticker.Stop()
	pm.Cancel()
	close(pm.TaskBase.Results)
	close(pm.TaskBase.Errors)
	return nil
}

// Results ...
func (pm *SocketsMonitor) Results() <-chan interface{} {
	return pm.TaskBase.Results
}

// Errors ...
func (pm *SocketsMonitor) Errors() <-chan error {
	return pm.TaskBase.Errors
}
