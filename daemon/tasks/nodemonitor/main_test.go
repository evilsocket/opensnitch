package nodemonitor

import (
	"context"
	"encoding/json"
	"syscall"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/tasks"
)

var tkMgr = tasks.NewTaskManager()

func TestNodeMonitor(t *testing.T) {
	taskName, nodeMon := New("my-node", "1s", false)
	activity := false
	var ctx context.Context
	var err error
	var sysinfoRaw string

	t.Run("AddTask", func(t *testing.T) {
		ctx, err = tkMgr.AddTask(taskName, nodeMon)
		if err != nil {
			t.Error("TaskManager.AddTask() error:", err)
		}
	})

	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				goto Exit
			case err := <-nodeMon.Errors():
				t.Error("Error via channel Errors():", err)
			case temp := <-nodeMon.Results():
				var ok bool
				sysinfoRaw, ok = temp.(string)
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
		var sysinfo syscall.Sysinfo_t
		err = json.Unmarshal([]byte(sysinfoRaw), &sysinfo)
		if err != nil {
			t.Error("Error unmarshaling response:", err)
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
		t.Error("Error: task active after being removed/stopped")
	}
}
