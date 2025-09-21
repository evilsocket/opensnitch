// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package config

import (
	"encoding/json"

	"github.com/evilsocket/opensnitch/daemon/tasks/scheduler"
)

type NotifyType string
type ActionType string
type ActionData string

type ReportType string

var (
	Enabled       = "enabled"
	NotifyDesktop = NotifyType("desktop")

	ActionDelete = ActionType("delete")
	ActionKill   = ActionType("kill")
	ActionNotify = ActionType("notify")

	ReportFile = ReportType("file")
)

type NotifyStatus struct {
	Type    NotifyType `json:"type"`
	Message string     `json:"message"`
}

type NotifyOpts struct {
	Success NotifyStatus `json:"success"`
	Error   NotifyStatus `json:"error"`
	Enabled bool         `json:"enabled"`
}

type ActionsOpts struct {
	Type ActionType
	Data ActionData
}

type List struct {
	Name string
}

type ExclusionsOpts struct {
	Dirs  []string
	Files []string
	Tags  []string
}

type ReportOpts struct {
	Type   ReportType
	Path   string
	Format string
	Sync   bool
}

// ScanOpts holds the options of each tool.
// Some fields will be common to all tools, and some will be ignored if they
// don't apply to a particular tool (MaxSize -> debsums)
// yara tool configuration example:
// "options": {
//    "debug": false,
//    "recursive": true,
//    "scanprocs": false,
//    "fastscan": false,
//    "maxSize": 0,
//    "maxProcessMem": 0,
//    "maxRunningTime": "1h",
//    "threads": 1,
//    "priority": 0,
//    "reports": [
//        {
//            "type": "file",
//            "path": "/etc/opensnitchd/tasks/iocscanner/reports",
//            "format": ""
//        }
//    ],
//    "dirs": ["/dev/shm", "/tmp",
//	"/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly",
//	],
//	"files": ["/etc/ld.so.config"],
//	"rules": [ "/etc/opensnitchd/tasks/iocscanner/rules/*.yar" ]
// }
type ScanOpts struct {
	Dirs  []string
	Files []string
	Rules []string
	Tags  []string

	Exclusions ExclusionsOpts

	Reports []ReportOpts

	MaxRunningTime string
	// -z size --skip-larger=size
	// Skip files larger than the given size in  bytes
	MaxSize int
	//MaxProcessMem  int

	// max number of threads (yara)
	// 0 == use all available cores.
	Threads int

	// nice value: -20 (maximum priority) to 20 (less priority)
	Priority int

	ScanProcs bool
	Recursive bool
	FastScan  bool
	Debug     bool
}

// ToolOpts holds the configuration of the tools to launch.
// IOCScanner understands 3 tools: yara, script and debsums/dpkg. Defined by
// the Name field.
// Each tool has its own configuration, sharing some fields.
// Coniguration example:
// {
//   "name": "yara",
//   "msgstart": "IOC scanner yara started",
//   "msgend": "IOC scanner yara finished",
//   "enabled": false,
//   "cmd": ["/usr/bin/yara"],
//   "dataDir": "/etc/opensnitchd/tasks/iocscanner/data/",
//   "reports": [
//      {
//        "type": "file",
//        "path": "/etc/opensnitchd/tasks/iocscanner/reports",
//        "format": ""
//      }
//   ],
//   (...)
// },
type ToolOpts struct {
	Options ScanOpts
	Cmd     []string

	// Name defines the tool to launch (yara, scripts, debsums, dpkg)
	Name string

	// MsgStart allows to use a custom message for the notification
	MsgStart string
	MsgEnd   string

	// to store temp files, rules, etc
	DataDir string

	// depending on what we execute, we may need to increase this buffer to
	// read the output from the command.
	ReadBuffer int
	// read workers to handle stdout
	Workers int
	Enabled bool
}

// IOCConfig holds the configuration of a task instance.
// The Schedule object holds when the tools defined will be launched.
// Tools holds the defined tools to run.
// TODO: actions
//
//  "schedule": [
//  {
//    "weekday": [0,1,2,3,4,5,6],
//    "time": ["09:55:00", "20:15:20", "22:10:50", "23:45:00", "01:17:55"],
//    "hour": [],
//    "minute": [],
//    "second": []
//  }
//  ],
//  "tools": [
//  {
//    "name": "script-ls",
//    "enabled": false,
//    "cmd": ["ls", "/tmp"],
//    "options": {
//        "recursive": false,
//        "priority": 0,
//        "dirs": [],
//        "files": []
//    }
//  },
//]
type IOCConfig struct {
	Schedule []scheduler.Config `json:"schedule"`
	Tools    []ToolOpts
	Notify   NotifyOpts
	Actions  []ActionsOpts
	Interval string
}

func LoadConfig(data map[string]interface{}) (IOCConfig, error) {
	dataStr, err := json.Marshal(data)
	if err != nil {
		return IOCConfig{}, err
	}
	var dc IOCConfig
	err = json.Unmarshal([]byte(dataStr), &dc)
	return dc, err
}
