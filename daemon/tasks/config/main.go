package config

// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/fsnotify/fsnotify"
)

var (
	DefaultCfgFile = "/etc/opensnitchd/tasks/tasks.json"
)

// TaskData represents the configuration of a task.
// For example:
// {
//   "name": "sockets-monitor",
//   "data": {"protocol": 1, "state": "all", array: [...], ...}
// }
// The data field must be a JSON object.
// Each task can unmarshal the object to its own JSON object.
type TaskData struct {
	// Parent holds the name of the parent task
	Parent string

	// Name holds the name of this particular task.
	// It must be unique if you want to run multiple instances of the same task.
	Name string
	Data map[string]interface{}
}

// TaskConfig holds the information of each task. The name, the configuration
// file and if its enabled or not.
// The name of the task must be the one defined in each task: task.Name
type TaskConfig struct {
	Name       string
	ConfigFile string
	Enabled    bool
}

// TaskList holds the list of existing tasks.
//
// {
//   "list": [
//    {
//      "name": "node-monitor",
//		"enabled": true,
//      "file": "/etc/opensnitchd/tasks/node-monitor/node-monitor.json",
//    },
//    ...
//   ]
// }
//
type TasksList struct {
	Tasks []TaskConfig
}

type Loader struct {
	watcher           *fsnotify.Watcher
	Tasks             []TaskConfig
	CfgFile           string
	stopLiveReload    chan struct{}
	TaskChanged       chan string
	liveReloadRunning bool

	sync.RWMutex
}

// NewTasksLoader returns a new configuration loader object.
// It'll monitor the configuration files for changes.
func NewTasksLoader() (*Loader, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Loader{
		liveReloadRunning: false,
		watcher:           watcher,
		stopLiveReload:    make(chan struct{}),
		TaskChanged:       make(chan string),
	}, nil
}

func (l *Loader) Load(path string) ([]TaskConfig, error) {
	if path == "" {
		path = DefaultCfgFile
	}
	log.Debug("[tasks] Loader.Load() config file: %s", path)

	raw, err := ioutil.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("error reading tasks list file %s: %s", path, err)
	}
	var tasks TasksList
	err = json.Unmarshal(raw, &tasks)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling config file %s: %s", path, err)
	}
	l.Tasks = tasks.Tasks
	l.CfgFile = path

	if !l.isLiveReloadRunning() {
		go l.liveReloadWorker()
	}

	return l.Tasks, nil
}
