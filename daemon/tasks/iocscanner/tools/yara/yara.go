// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package yara

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	// name: "yara"
	// name: "yara-yarify-ruleset"
	// name: "yara-virustotal-ruleset"
	Prefix = "yara"
)

var (
	DataDir        = "/etc/opensnitchd/tasks/iocscanner/data/yara"
	reportsPrefix  = "/ioc-report-"
	scanListPrefix = ".opensnitch-yarascan.*.txt"
)

type YaraTool struct {
	base.ToolBase

	ScanList *os.File
}

func (y *YaraTool) Start() {
	y.Executer.SetPriority(y.Options.Priority)
	y.Executer.Start(y.Cmd, y.Cmdline)
}

func (y *YaraTool) Log(line string) {
	if y.Logger == nil {
		return
	}

	y.Logger.Write([]byte(line))
}

func (y *YaraTool) TransformLogline(line string) string {
	// TODO: json, etc
	return line
}

func (y *YaraTool) Cleanup() {
	log.Debug("[yara-tool] Cleanup() %s", y.Name)
	if y.Logger != nil {
		y.Logger.Close()
	}

	if y.ScanList != nil {
		y.ScanList.Close()
		os.Remove(y.ScanList.Name())
		log.Error("[yara-tool] removing %s", y.ScanList.Name())
	}
}

func (y *YaraTool) Stop() {
	log.Debug("[yara-tool] Stop() %s", y.Name)
	y.Cleanup()
	y.Executer.Stop()
}

// Creates a new yara scan with the given configuration.
func New(opts config.ToolOpts) *YaraTool {
	log.Trace("[IOCScanner] creating yara tool: %s", opts.Name)
	ctx, cancel := context.WithCancel(context.Background())

	if opts.ReadBuffer == 0 {
		opts.ReadBuffer = 1
	}

	yara := YaraTool{
		ToolBase: base.ToolBase{
			ToolOpts: opts,
			Executer: executer.Executer{
				Ctx:    ctx,
				Cancel: cancel,
				Stdout: make(chan string),
				Stderr: make(chan string),
			},
		},
	}
	yara.SetWorkers(opts.Workers)
	yara.Name = opts.Name
	if yara.Name == "" {
		yara.Name = "yara"
	}
	if yara.DataDir == "" {
		yara.DataDir = DataDir
	}
	if !core.Exists(yara.DataDir) {
		os.MkdirAll(yara.DataDir, 0700)
	}
	if yara.MsgStart == "" {
		yara.MsgStart = base.MsgStart
	}
	if yara.MsgEnd == "" {
		yara.MsgEnd = base.MsgEnd
	}

	if !strings.HasPrefix(opts.Name, "yara") {
		log.Warning("buildYaraCmdline: invalid yara config: %+v", opts)
		return nil
	}

	for _, rpt := range yara.Options.Reports {
		if rpt.Path != "" {
			if !core.Exists(rpt.Path) {
				os.MkdirAll(rpt.Path, 0700)
			}
			// TODO: parse format

			var err error
			now := time.Now()
			reportName := fmt.Sprint(
				rpt.Path,
				reportsPrefix, yara.Name,
				now.Format("02-01-2006T15:04:05"), ".log",
			)
			// TODO: check for duplicated reports
			yara.Logger, err = os.OpenFile(reportName, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				log.Warning("[IOCScanner][yara] warning: %s", err)
			}
		}
	}

	cmd := opts.Cmd[0]
	yara.Cmd = cmd
	// -g print tags
	// -s print strings
	// -w no warnings
	cmdline := []string{"--print-tags", "--no-warnings"}

	if yara.Options.Debug {
		cmdline = append(cmdline, "--print-strings")
	}
	if yara.Options.Recursive {
		cmdline = append(cmdline, "--recursive")
	}
	if yara.Options.FastScan {
		cmdline = append(cmdline, "--fast-scan")
	}
	if yara.Options.Threads > 0 {
		cmdline = append(cmdline,
			[]string{fmt.Sprint("--threads=", yara.Options.Threads)}...,
		)
	}
	if yara.Options.MaxRunningTime != "" {

		duration, err := time.ParseDuration(yara.Options.MaxRunningTime)
		if err == nil {
			cmdline = append(cmdline, []string{fmt.Sprint("--timeout=", duration.Seconds())}...)
		} else {
			log.Warning("[IOCScanner][yara] invalid MaxRunningTime %s: %s", yara.Options.MaxRunningTime, err)

		}
	}
	if yara.Options.MaxSize > 0 {
		cmdline = append(cmdline, []string{fmt.Sprint("--skip-larger=", yara.Options.MaxSize)}...)
	}
	if len(yara.Options.Tags) > 0 {
		for _, tag := range yara.Options.Tags {
			cmdline = append(cmdline, []string{fmt.Sprint("--tag=", tag)}...)
		}
	}
	if len(yara.Options.Rules) == 0 {
		log.Warning("yara tool: no rules specified")
		return nil
	}
	// remember that wildcards are expanded by bash, so we need to expand it
	// if the user has specified wildcards.
	for _, r := range yara.Options.Rules {
		matches, err := filepath.Glob(r)
		if err != nil {
			cmdline = append(cmdline, []string{r}...)
			continue
		}
		for _, m := range matches {
			cmdline = append(cmdline, []string{m}...)
		}

	}

	scanDirs := len(yara.Options.Dirs)
	scanFiles := len(yara.Options.Files)
	if scanFiles+scanDirs > 1 {
		//--scan-list

		if scanDirs == 0 {
			cmdline = append(cmdline, yara.Options.Files...)
		} else if scanFiles == 0 {
			cmdline = append(cmdline, yara.Options.Dirs...)
		} else {
			//os.Remove(yara.DataDir + scanListPrefix + "*")

			var err error
			yara.ScanList, err = os.CreateTemp(yara.DataDir, scanListPrefix)
			if err != nil {
				log.Warning("Yara warning, DataDir does not exist %s: %s", yara.DataDir, err)
				return nil
			}

			for _, f := range yara.Options.Files {
				yara.ScanList.Write([]byte(f))
				yara.ScanList.Write([]byte("\n"))
			}
			for _, d := range yara.Options.Dirs {
				yara.ScanList.Write([]byte(d))
				yara.ScanList.Write([]byte("\n"))
			}

			cmdline = append(cmdline, []string{"--scan-list", yara.ScanList.Name()}...)
		}

	} else if scanFiles == 1 {
		cmdline = append(cmdline, yara.Options.Files...)
	} else if scanDirs == 1 {
		cmdline = append(cmdline, yara.Options.Dirs...)
	}
	//if yara.Options.ScanProcs {
	//    listCachedProcs()
	//    listProcs()
	//}

	log.Trace("[IOCScanner] yara cmdline: %s %v", cmd, cmdline)
	yara.Cmdline = cmdline

	return &yara
}
