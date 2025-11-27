// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package base

import (
	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/config"
	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/tools/executer"
	"os"
)

const (
	MsgStart = "IOC scanner started"
	MsgEnd   = "IOC scanner finished"

	PropName     = "name"
	PropMsgStart = "msgstart"
	PropMsgEnd   = "msgend"
)

type ToolBase struct {
	executer.Executer
	config.ToolOpts

	Logger   *os.File
	Cmdline  []string
	Name     string
	MsgStart string
	MsgEnd   string
	Cmd      string
	workers  int
}

func (t *ToolBase) GetProperty(prop string) string {
	switch prop {
	case PropName:
		return t.Name
	case PropMsgStart:
		return t.MsgStart
	case PropMsgEnd:
		return t.MsgEnd
	}
	return ""
}

func (t *ToolBase) Log(line string) {
}

func (t *ToolBase) TransformLogline(line string) string {
	return line
}

func (t *ToolBase) Done() <-chan struct{} {
	return t.Executer.Ctx.Done()
}

func (t *ToolBase) Stdout() chan string {
	return t.Executer.Stdout
}

func (t *ToolBase) Stderr() chan string {
	return t.Executer.Stderr
}

func (t *ToolBase) Cleanup() {}

func (t *ToolBase) Workers() int {
	return t.workers
}

func (t *ToolBase) SetWorkers(wrks int) {
	t.workers = wrks
	if wrks == 0 {
		t.workers = 1
	}
}

type Tool interface {
	Start()
	Stop()
	Running() bool
	GetProperty(string) string
	Log(string)
	TransformLogline(string) string
	Stdout() chan string
	Stderr() chan string
	Workers() int
	Done() <-chan struct{}
	Cleanup()
}
