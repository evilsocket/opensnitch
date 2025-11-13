// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package generic

import (
	"context"
	"fmt"
	"os"
	//"path/filepath"
	"strings"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/config"
	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/tools/base"
	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/tools/executer"
)

const (
	// Prefix is the name that identifies this tool in the configuration.
	// It must appear at the beginning of the name.
	// You can append more details after it, in order to create multiple instances of this tool.
	// Examples:
	// name: "script"
	// name: "script-clamav"
	// name: "script-unide"
	// name: "script-decloaker-hidden-procs"
	Prefix = "script"
)

type GenericTool struct {
	base.ToolBase
}

func (d *GenericTool) Log(line string) {
	if d.Logger == nil {
		return
	}

	d.Logger.Write([]byte(line))
}

func (d *GenericTool) Start() {
	log.Debug("[generic-tool] Start() %s, %v", d.Cmd, d.Cmdline)
	d.Executer.SetPriority(d.Options.Priority)
	d.Executer.Start(d.Cmd, d.Cmdline)
}

func (d *GenericTool) TransformLogline(line string) string {
	for _, dir := range d.Options.Exclusions.Dirs {
		if strings.Contains(line, dir) {
			return ""
		}
	}
	for _, file := range d.Options.Exclusions.Files {
		if strings.Contains(line, file) {
			return ""
		}
	}

	return line
}

func (d *GenericTool) Cleanup() {
	if d.Logger != nil {
		d.Logger.Close()
	}
}

func (d *GenericTool) Stop() {
	log.Debug("[generic-tool] Stop() %s", d.Name)
	d.Cleanup()
	d.Executer.Stop()
}

// Creates a new generic scan with the given configuration.
func New(opts config.ToolOpts) *GenericTool {
	log.Trace("[IOCScanner] creating generic tool: %s", opts.Name)
	ctx, cancel := context.WithCancel(context.Background())

	if opts.ReadBuffer == 0 {
		opts.ReadBuffer = 1
	}

	generic := GenericTool{
		ToolBase: base.ToolBase{
			ToolOpts: opts,
			Executer: executer.Executer{
				Ctx:    ctx,
				Cancel: cancel,
				Stdout: make(chan string, opts.ReadBuffer),
				Stderr: make(chan string, 0),
			},
		},
	}
	generic.SetWorkers(opts.Workers)
	generic.Name = opts.Name
	if generic.Name == "" {
		generic.Name = "script"
	}
	if generic.MsgStart == "" {
		generic.MsgStart = base.MsgStart
	}
	if generic.MsgEnd == "" {
		generic.MsgEnd = base.MsgEnd
	}

	if !strings.HasPrefix(opts.Name, "script") {
		log.Warning("[IOCScanner][generic]: invalid generic config: %+v", opts)
		return nil
	}

	for _, rpt := range generic.Options.Reports {
		switch rpt.Type {
		case config.ReportFile:
			if rpt.Path != "" {
				if !core.Exists(rpt.Path) {
					os.MkdirAll(rpt.Path, 0700)
				}

				var err error
				now := time.Now()
				reportName := fmt.Sprint(rpt.Path, "/ioc-report-", generic.Name, "-", now.Format("02-01-2006T15:04:05"), ".log")
				// TODO: check for duplicated reports, and rotate
				generic.Logger, err = os.OpenFile(reportName, os.O_RDWR|os.O_CREATE, 0600)
				if err != nil {
					log.Warning("[IOCScanner][generic] warning: %s", err)
				}
			}
		}
		// TODO: parse format
	}

	cmd := opts.Cmd[0]
	generic.Cmd = cmd
	cmdline := opts.Cmd[1:]

	if generic.Options.MaxRunningTime != "" {
		// TODO: set timeout
	}

	generic.Cmdline = cmdline

	return &generic
}
