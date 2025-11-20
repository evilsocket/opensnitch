package iocscanner

// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

import (
	"context"
	//"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	//"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/tasks/base"
	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/config"
	baseT "github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/tools/base"
	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/tools/dpkg"
	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/tools/executer"
	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/tools/generic"
	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/tools/yara"
	"github.com/evilsocket/opensnitch/daemon/tasks/scheduler"
)

// Multiple instances of this task could coexist.
// One for monitoring processes, another one for files
var Name = "IOC-scanner"

// Config of this task
type Config struct {
	Interval string
}

// IOCScanner monitors .
type IOCScanner struct {
	base.TaskBase

	mu       *sync.RWMutex
	Ticker   *time.Ticker
	Executer *executer.Executer
	Config   config.IOCConfig
	Tools    []baseT.Tool
	Interval string
	Hostname string
}

// New returns a new IOCScanner
func New(name string, taskcfg map[string]interface{}, stopOnDisconnect bool) (string, *IOCScanner) {
	iocs := &IOCScanner{
		TaskBase: base.TaskBase{
			ID:               base.REDFLAGS,
			Name:             Name,
			Results:          make(chan interface{}),
			Errors:           make(chan error),
			StopOnDisconnect: stopOnDisconnect,
		},
		// used to identify this host in the report
		Hostname: core.GetHostname(),
		mu:       &sync.RWMutex{},
		Executer: executer.New(),
	}

	iocs.Interval = taskcfg["interval"].(string)
	if iocs.Interval == "" {
		iocs.Interval = "5s"
	}

	cfg, err := config.LoadConfig(taskcfg)
	if err != nil {
		log.Warning("IOCScanner config warning: %s", err)
	}
	iocs.Config = cfg
	log.Trace("IOCScanner Config: %+v\n", cfg)

	return name, iocs
}

// Start ...
func (pm *IOCScanner) Start(ctx context.Context, cancel context.CancelFunc) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pm.Ctx = ctx
	pm.Cancel = cancel

	pm.Tools = []baseT.Tool{}
	for _, opts := range pm.Config.Tools {
		if strings.HasPrefix(opts.Name, yara.Prefix) && opts.Enabled {
			yaraT := yara.New(opts)
			if yaraT != nil {
				pm.Tools = append(pm.Tools, yaraT)
			}
		}
		if (strings.HasPrefix(opts.Name, dpkg.PrefixDebsums) || strings.HasPrefix(opts.Name, dpkg.PrefixDpkg)) && opts.Enabled {
			dpkgT := dpkg.New(opts)
			if dpkgT != nil {
				pm.Tools = append(pm.Tools, dpkgT)
			}
		}
		if strings.HasPrefix(opts.Name, generic.Prefix) && opts.Enabled {
			genericT := generic.New(opts)
			if genericT != nil {
				pm.Tools = append(pm.Tools, genericT)
			}
		}
	}

	if len(pm.Tools) == 0 {
		// fine
		return fmt.Errorf("no tools configured")
	}
	for n, schedCfg := range pm.Config.Schedule {
		go func() {
			sched := scheduler.New(ctx, cancel, schedCfg)
			sched.Start()

			for {
				select {
				case <-sched.Ctx.Done():
					goto Exit
				case tick := <-sched.Tick():
					log.Trace("[%d] IOCScanner scheduler tick: %v\n", n, tick)

					for _, t := range pm.Tools {
						// XXX: should we skip new requests to initiate tasks when previous instances
						// are already running, or should we stop previous instances?
						// or make it configurable?
						if t.Running() {
							log.Trace("IOCScanner tick, task already running: %s", t.GetProperty(baseT.PropName))
							continue
						}
						log.Trace("[%d] IOCScanner tick, running task: %s\n", n, t.GetProperty(baseT.PropName))
						pm.runTool(t)

					}
				}
			}
		Exit:
			log.Debug("[IOCScanner] scheduler stopped")
			sched.Stop()
		}()
	}

	// ~200µs (string()) vs ~60ns
	//pm.TaskBase.Results <- unsafe.String(unsafe.SliceData(pJSON), len(pJSON))

	log.Debug("[IOCScanner] stopped")
	return nil
}

func (pm *IOCScanner) GetName() string {
	return Name
}

// Pause stops temporarily the task. For example it might be paused when the
// connection with the GUI (server) is closed.
func (pm *IOCScanner) Pause() error {
	// TODO
	return nil
}

// Resume stopped tasks.
func (pm *IOCScanner) Resume() error {
	// TODO
	return nil
}

// Stop ...
func (pm *IOCScanner) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	log.Debug("[IOCScanner] Stop()")

	if pm.StopOnDisconnect {
		log.Debug("[IOCScanner] ignoring Stop()")
		return nil
	}

	for _, t := range pm.Tools {
		log.Debug("[IOCScanner] stopping tool %s", t.GetProperty(baseT.PropName))
		t.Stop()
	}

	if pm.Cancel != nil {
		pm.Cancel()
	}
	return nil
}

// Results ...
func (pm *IOCScanner) Results() <-chan interface{} {
	return pm.TaskBase.Results
}

// Errors ...
func (pm *IOCScanner) Errors() <-chan error {
	return pm.TaskBase.Errors
}
