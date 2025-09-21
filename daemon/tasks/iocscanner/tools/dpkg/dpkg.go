// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package dpkg

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

type DpkgTool struct {
	base.ToolBase
}

func (d *DpkgTool) Log(line string) {
	if d.Logger == nil {
		return
	}

	d.Logger.Write([]byte(line))
}

func (d *DpkgTool) Start() {
	log.Debug("[dpkg-tool] Start() %s, %v", d.Cmd, d.Cmdline)
	d.Executer.SetPriority(d.Options.Priority)
	d.Executer.Start(d.Cmd, d.Cmdline)
}

func (d *DpkgTool) TransformLogline(line string) string {
	/*if strings.HasPrefix(line, "missing") {
		return ""
	}*/
	for _, dir := range d.Options.Exclusions.Dirs {
		path := strings.Fields(line)
		if len(path) >= 1 && strings.HasPrefix(path[1], dir) {
			return ""
		}
	}
	for _, file := range d.Options.Exclusions.Files {
		path := strings.Fields(line)
		if len(path) > 1 && strings.HasSuffix(path[1], file) {
			return ""
		}
	}
	for _, tag := range d.Options.Exclusions.Tags {
		path := strings.Fields(line)
		if len(path) > 0 && strings.HasPrefix(path[0], tag) {
			return ""
		}
	}

	if len(d.Options.Dirs) == 0 && len(d.Options.Files) == 0 {
		return line
	}

	for _, dir := range d.Options.Dirs {
		path := strings.Fields(line)
		if len(path) > 1 && strings.HasPrefix(path[1], dir) {
			return line
		}
	}
	for _, file := range d.Options.Files {
		path := strings.Fields(line)
		if len(path) > 0 && strings.HasSuffix(path[1], file) {
			return line
		}
	}

	return line
}

func (d *DpkgTool) Cleanup() {
	if d.Logger != nil {
		d.Logger.Close()
	}
}

func (d *DpkgTool) Stop() {
	log.Debug("[dpkg-tool] Stop() %s", d.Name)
	d.Cleanup()
	d.Executer.Stop()
}

// Creates a new dpkg scan with the given configuration.
func New(opts config.ToolOpts) *DpkgTool {
	log.Trace("[IOCScanner] creating dpkg tool: %s", opts.Name)
	ctx, cancel := context.WithCancel(context.Background())

	if opts.ReadBuffer == 0 {
		opts.ReadBuffer = 1
	}

	dpkg := DpkgTool{
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
	dpkg.SetWorkers(opts.Workers)
	dpkg.Name = opts.Name
	if dpkg.Name == "" {
		dpkg.Name = "dpkg"
	}
	if dpkg.MsgStart == "" {
		dpkg.MsgStart = base.MsgStart
	}
	if dpkg.MsgEnd == "" {
		dpkg.MsgEnd = base.MsgEnd
	}

	if !strings.HasPrefix(opts.Name, "debsums") && !strings.HasPrefix(opts.Name, "dpkg") {
		log.Warning("DpkgTool: invalid dpkg config: %+v", opts)
		return nil
	}

	for _, rpt := range dpkg.Options.Reports {
		switch rpt.Type {
		case config.ReportFile:
			if rpt.Path != "" {
				if !core.Exists(rpt.Path) {
					os.MkdirAll(rpt.Path, 0700)
				}

				var err error
				now := time.Now()
				reportName := fmt.Sprint(rpt.Path, "/ioc-report-", dpkg.Name, "-", now.Format("02-01-2006T15:04:05"), ".log")
				// TODO: check for duplicated reports
				dpkg.Logger, err = os.OpenFile(reportName, os.O_RDWR|os.O_CREATE, 0600)
				if err != nil {
					log.Warning("[IOCScanner][dpkg] warning: %s", err)
				}
			}
		}
		// TODO: parse format
	}

	cmd := opts.Cmd[0]
	dpkg.Cmd = cmd
	cmdline := opts.Cmd[1:]

	if dpkg.Options.MaxRunningTime != "" {
		// TODO
	}

	log.Trace("[IOCScanner] dpkg cmdline: %s %v", cmd, cmdline)
	dpkg.Cmdline = cmdline

	return &dpkg
}
