// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package iocscanner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/tools/base"
	//"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner/tools/dpkg"
)

// runTool listens for results from the executed task
func (pm *IOCScanner) runTool(tool base.Tool) {
	start := time.Now()

	report := fmt.Sprintf("==== %s - %s (%s) ====\n\n\n", tool.GetProperty(base.PropName), pm.Hostname, start.Format("02-01-2006, 15:04:05"))

	go func() {
		var wg sync.WaitGroup
		for i := 0; i < tool.Workers(); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				for {
					select {
					case <-tool.Done():
						goto Exit
						//case <-pm.Executer.Stderr:
						//	goto Exit
					case logline := <-tool.Stdout():
						// FIXME: this is suboptimal. If the output is too large, like debsums output (~60MB),
						// we may consume up to some GB of ram.
						report += tool.TransformLogline(logline)
					}
				}
			Exit:
				scanFinished := fmt.Sprintf("\n\n=== %s - (%s) ===\n", tool.GetProperty(base.PropName), time.Since(start).Truncate(time.Second))
				report += scanFinished
				tool.Log(report)

				// we're using QTextEdit.setHtml() to display the report, so new lines must be converted to <br>
				pm.TaskBase.Results <- strings.ReplaceAll(report, "\n", "<br>")
			}()
		}
		wg.Wait()
		//-----

		// TODO: decide what format to use for sending back the report to the GUI.
		// json will be more suitable.

		tool.Stop()
	}()

	tool.Start()
}
