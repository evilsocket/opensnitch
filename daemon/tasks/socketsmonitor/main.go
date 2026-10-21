package socketsmonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks/base"
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
	base.TaskBase
	mu     *sync.RWMutex
	Ticker *time.Ticker

	Config *monConfig
	states uint8

	// stop the task if the daemon is disconnected from the GUI (server)
	StopOnDisconnect bool
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
	var err error
	// These came straight off the wire from the GUI. A missing field, or one
	// of the wrong JSON type, used to panic the type assertion and take the
	// whole daemon down; now it is a config error the caller can report.
	if v, ok := cfg["interval"].(string); ok {
		newCfg.Interval = v
	}
	if newCfg.State, err = cfgUint8(cfg, "state"); err != nil {
		return nil, err
	}
	if newCfg.Proto, err = cfgUint8(cfg, "proto"); err != nil {
		return nil, err
	}
	if newCfg.Family, err = cfgUint8(cfg, "family"); err != nil {
		return nil, err
	}

	if newCfg.Interval == "" {
		newCfg.Interval = "5s"
	}

	return &newCfg, nil
}

// cfgUint8 reads a numeric field from the decoded JSON config. encoding/json
// decodes every number as float64, so that is the only valid dynamic type.
func cfgUint8(cfg map[string]interface{}, key string) (uint8, error) {
	v, ok := cfg[key]
	if !ok {
		return 0, fmt.Errorf("[sockmon] missing %q in config", key)
	}
	f, ok := v.(float64)
	if !ok {
		return 0, fmt.Errorf("[sockmon] %q must be a number, got %T", key, v)
	}
	return uint8(f), nil
}

// New returns a new SocketsMonitor
func New(name string, config interface{}, stopOnDisconnect bool) (*SocketsMonitor, error) {
	cfg, err := initConfig(config)
	if err != nil {
		return nil, err
	}
	return &SocketsMonitor{
		TaskBase: base.TaskBase{
			Name:    Name,
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
			default:
				// FIXME: ensure that dumpSockets() are not overlapped
				socketList := pm.dumpSockets()
				sockJSON, err := json.Marshal(socketList)
				if err != nil {
					pm.TaskBase.Errors <- err
				}

				pm.TaskBase.Results <- unsafe.String(unsafe.SliceData(sockJSON), len(sockJSON))

				<-pm.Ticker.C
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

	log.Debug("[task.SocketsMonitor] Stop()")
	if pm.Ticker != nil {
		pm.Ticker.Stop()
	}
	if pm.Cancel != nil {
		pm.Cancel()
	}
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
