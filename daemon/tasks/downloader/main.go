// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package downloader

import (
	"context"
	//"encoding/json"
	//"fmt"
	"sync"
	"time"
	//"unsafe"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks/base"
)

var (
	// Name identifies the type of task of the instance.
	Name = "downloader"

	DefaultInterval = "6h"
	DefaultTimeout  = "5s"

	SuccessMsg = "[blocklists] lists updated"
)

// Downloader downloads files at interval times.
type Downloader struct {
	base.TaskBase

	mu     *sync.RWMutex
	Ticker *time.Ticker
	Config DownloaderConfig
	Urls   map[string]string
}

// New returns a new Downloader
func New(config map[string]interface{}, stopOnDisconnect bool) *Downloader {

	cfg, err := loadConfig(config)
	if err != nil {
		log.Warning("Downloader config warning: %s", err)
	}
	log.Debug("[Downloader] New: %s -> %+v", Name, cfg)
	return &Downloader{
		TaskBase: base.TaskBase{
			ID:               base.DOWNLOADER,
			Name:             Name,
			Results:          make(chan interface{}),
			Errors:           make(chan error),
			StopOnDisconnect: stopOnDisconnect,
		},
		mu:     &sync.RWMutex{},
		Urls:   make(map[string]string),
		Config: cfg,
	}
}

// Start ...
func (pm *Downloader) Start(ctx context.Context, cancel context.CancelFunc) error {
	pm.mu.Lock()

	pm.Ctx = ctx
	pm.Cancel = cancel

	log.Debug("[Downloader] config: %s\n%+v\n", pm.Name, pm.Config)

	interval, err := pm.parseInterval()
	if err != nil {
		log.Warning("[Downloader] Invalid interval: %s", err)
	}
	pm.Ticker = time.NewTicker(interval)
	timeout, err := pm.parseTimeout()
	if err != nil {
		log.Warning("[Downloader] Invalid timeout")
	}
	pm.loadUrls()

	pm.mu.Unlock()

	downMgr := NewDownloaderMgr(pm.Urls, timeout)
	progressExit := make(chan struct{})
	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				goto Exit
			default:
				// TODO: errors counter, and exit on errors > X
				// URLs may stop working, cert errors, etc.
				start := time.Now()
				log.Debug("[Downloader] urls: %+v, %v\n", pm.Config, time.Since(start))

				// this operation may last a lot of time. It depends on the download speed, the amount of urls, etc.
				onFinish := downMgr.Start()
				results := ""
				errors := 0
				go func(ctx context.Context) {
					for {
						select {
						case <-ctx.Done():
							goto downFinish
						case <-progressExit:
							goto downFinish
						case result := <-downMgr.Progress():
							// TODO: reply with a JSON so the GUI can parse and show the results per list.
							/*pJSON, err := json.Marshal(result)
							if err != nil {
								log.Debug("[Downloader] error parsing error: %s\n", err)
								pm.TaskBase.Errors <- err
								continue
							}*/
							log.Debug("[Downloader] finished: %d bytes, %s\n", result.Bytes, result.URL)

							if result.Error != nil || result.Bytes == 0 {
								errors++
								results = core.ConcatStrings(results, ", ", result.URL)
							}
						}
					}
				downFinish:
					log.Debug("[tasks.Downloader] stopped")
				}(ctx)
				onFinish.Wait()
				progressExit <- struct{}{}

				if pm.Config.Notify.Enabled {
					if errors > 0 {
						results = core.ConcatStrings("\n\nErrors:\n", results)
					}
					pm.TaskBase.Results <- core.ConcatStrings(SuccessMsg, results)
					pm.TaskBase.Results <- base.TaskResults{Type: 9999, Data: core.ConcatStrings(SuccessMsg, results)}
				}

				log.Debug("[Downloader] finished (%d): %s", len(pm.Urls), results)

				// TODO: parse notify

				<-pm.Ticker.C
			}
		}
	Exit:
		log.Debug("[tasks.Downloader] stopped: %+v", pm.Config)
	}(ctx)
	return err
}

func (pm *Downloader) GetName() string {
	return pm.Name
}

// Pause stops temporarily the task. For example it might be paused when the
// connection with the GUI (server) is closed.
func (pm *Downloader) Pause() error {
	return nil
}

// Resume stopped tasks.
func (pm *Downloader) Resume() error {
	return nil
}

// Stop ...
func (pm *Downloader) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	log.Debug("Downloader.Stop() %s", pm.Name)

	/*if pm.StopOnDisconnect {
		log.Debug("[task.Downloader] ignoring Stop()")
		return nil
	}*/
	if pm.Ticker != nil {
		pm.Ticker.Stop()
	}
	if pm.Cancel != nil {
		pm.Cancel()
	}
	close(pm.TaskBase.Results)
	close(pm.TaskBase.Errors)
	return nil
}

// Results ...
func (pm *Downloader) Results() <-chan interface{} {
	return pm.TaskBase.Results
}

// Errors ...
func (pm *Downloader) Errors() <-chan error {
	return pm.TaskBase.Errors
}
