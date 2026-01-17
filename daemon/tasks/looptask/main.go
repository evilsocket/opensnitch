// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package looptask

import (
	"context"
	//"fmt"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks/base"
)

// Example of a task that prints a message at regular intervals.

var Name = "looper"

// Config of this task
type Config struct {
	Interval string
}

// Looper a file.
type Looper struct {
	base.TaskBase

	mu       *sync.RWMutex
	Ticker   *time.Ticker
	Interval string
}

func New(name, interval string) (string, *Looper) {
	return name, &Looper{
		TaskBase: base.TaskBase{
			ID:      9999,
			Name:    Name,
			Results: make(chan interface{}),
			Errors:  make(chan error),
		},
		Interval: interval,
		mu:       &sync.RWMutex{},
	}
}

// Start ...
func (fm *Looper) Start(ctx context.Context, cancel context.CancelFunc) error {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	fm.Ctx = ctx
	fm.Cancel = cancel

	if fm.Interval == "" {
		fm.Interval = "5s"
	}
	interval, err := time.ParseDuration(fm.Interval)
	if err != nil {
		return err
	}
	fm.Ticker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-ctx.Done():
				goto Exit
			case <-fm.Ticker.C:
				log.Info("[tasks.Looper] loooping %s", fm.Interval)
				fm.TaskBase.Results <- fm.Interval
			}
		}

	Exit:
		log.Debug("[tasks.Looper] stopped")
	}()
	return nil
}

// Pause stops temporarily the task. For example it might be paused when the
// connection with the GUI (server) is closed.
func (fm *Looper) Pause() error {
	// TODO
	return nil
}

// Resume stopped tasks.
func (fm *Looper) Resume() error {
	// TODO
	return nil
}

// Stop ...
func (fm *Looper) Stop() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if fm.Cancel != nil {
		fm.Cancel()
	}
	log.Debug("[task.looper] Stop()")
	if fm.Ticker != nil {
		fm.Ticker.Stop()
	}
	close(fm.TaskBase.Results)
	close(fm.TaskBase.Errors)
	return nil
}

// Results ...
func (fm *Looper) Results() <-chan interface{} {
	return fm.TaskBase.Results
}

// Errors ...
func (fm *Looper) Errors() <-chan error {
	return fm.TaskBase.Errors
}

func (fm *Looper) GetName() string {
	return Name
}
