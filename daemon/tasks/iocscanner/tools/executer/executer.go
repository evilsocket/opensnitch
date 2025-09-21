// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package executer

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"syscall"

	"github.com/evilsocket/opensnitch/daemon/log"
)

type Executer struct {
	Ctx    context.Context
	Cancel context.CancelFunc

	Stdout chan string
	Stderr chan string

	Priority  int
	isRunning bool
}

func New() *Executer {
	ctx, cancel := context.WithCancel(context.Background())
	return &Executer{
		Ctx:    ctx,
		Cancel: cancel,
		Stdout: make(chan string, 0),
		Stderr: make(chan string, 0),
	}
}

// Start launches the configured command.
// It's a blocking operation.
func (e *Executer) Start(bin string, args []string) {
	log.Debug("[executer] Start() %s %v\n", bin, args)
	cmd := exec.CommandContext(e.Ctx, bin, args...)
	e.isRunning = false

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Error("[executer] error: %s", err)
		return
	}

	// TODO: export StdoutPipe(), in order to allow io.Copy()
	go func() {
		stdoutReader := bufio.NewReader(stdout)
		for {
			select {
			case <-e.Ctx.Done():
				goto Exit
			default:
				str, err := stdoutReader.ReadString('\n')
				if err != nil || err == io.EOF {
					goto Exit
				}
				e.Stdout <- str
			}
		}
	Exit:
		log.Debug("[executer] stdout reader exit")
		e.Stop()
	}()
	log.Debug("[executer] Waiting... %s", bin)
	if err := cmd.Start(); err != nil {
		log.Error("Executer.Start() %s", err)
		return
	}
	e.isRunning = true
	defer func() { e.isRunning = false }()

	if cmd.Process != nil {
		syscall.Setpriority(syscall.PRIO_PROCESS, cmd.Process.Pid, e.Priority)
	} else {
		log.Debug("[executer] unable to the change process priority")
	}

	if err := cmd.Wait(); err != nil {
		// many cli tools/scripts can exit with error
		log.Debug("[executer] Wait error: %s", err)
	}
	log.Info("[executer] finished")

}

func (e *Executer) SetPriority(prio int) {
	e.Priority = prio
}

func (e *Executer) Running() bool {
	return e.isRunning
}

func (e *Executer) Stop() {
	if e.Cancel != nil {
		e.Cancel()
	}
}
