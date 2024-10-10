package pidmonitor

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/tasks"
)

var tkMgr = tasks.NewTaskManager()

func TestPIDMonitor(t *testing.T) {
	ourPID := os.Getpid()
	taskName, pidMon := New(ourPID, "1s", false)
	activity := false
	var ctx context.Context
	var err error
	var procRaw string

	t.Run("AddTask", func(t *testing.T) {
		ctx, err = tkMgr.AddTask(taskName, pidMon)
		if err != nil {
			t.Error("TaskManager.AddTask() error:", err)
		}
	})

	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				goto Exit
			case err := <-pidMon.Errors():
				t.Error("Error via channel Errors():", err)
			case temp := <-pidMon.Results():
				var ok bool
				procRaw, ok = temp.(string)
				if !ok {
					t.Error("Error on Results() channel:", temp)
					goto Exit
				}
				activity = true
			}
		}
	Exit:
	}(ctx)
	time.Sleep(3 * time.Second)
	if !activity {
		t.Error("Error: no activity after 5s")
	}

	t.Run("Unmarshal response", func(t *testing.T) {
		var proc procmon.Process
		err = json.Unmarshal([]byte(procRaw), &proc)
		if err != nil {
			t.Error("Error unmarshaling response:", err)
		}
		if proc.ID != ourPID {
			t.Error("invalid Process object received:", ourPID, proc)
		}
	})

	t.Run("RemoveTask", func(t *testing.T) {
		err = tkMgr.RemoveTask(taskName)
		if err != nil {
			t.Error("RemoveTask() error:", err)
		}
		if tk, found := tkMgr.GetTask(taskName); found {
			t.Error("Task not removed:", tk)
		}
	})

	activity = false
	time.Sleep(2 * time.Second)
	if activity {
		t.Error("Task active after being removed/stopped")
	}
}
