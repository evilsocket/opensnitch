package tasks

import (
	"context"
	"testing"
)

type BasicTask struct {
	TaskBase
	Name string
}

func (pm *BasicTask) Start(ctx context.Context, cancel context.CancelFunc) error {
	return nil
}
func (pm *BasicTask) Pause() error {
	return nil
}
func (pm *BasicTask) Resume() error {
	return nil
}
func (pm *BasicTask) Stop() error {
	return nil
}
func (pm *BasicTask) Errors() <-chan error {
	return pm.TaskBase.Errors
}
func (pm *BasicTask) Results() <-chan interface{} {
	return pm.TaskBase.Results
}

var basicTask = BasicTask{
	TaskBase: TaskBase{
		Results: make(chan interface{}),
		Errors:  make(chan error),
	},
	Name: "basic-task",
}

func TestTaskManager(t *testing.T) {
	tkMgr := NewTaskManager()

	t.Run("AddTask", func(t *testing.T) {
		_, err := tkMgr.AddTask(basicTask.Name, &basicTask)
		if err != nil {
			t.Error("AddTask():", err)
		}
	})

	t.Run("GetTask", func(t *testing.T) {
		if tk, found := tkMgr.GetTask(basicTask.Name); !found {
			t.Error("GetTask() not found:", tk)
		}
	})

	t.Run("RemoveTask", func(t *testing.T) {
		if err := tkMgr.RemoveTask(basicTask.Name); err != nil {
			t.Error("RemoveTask() error:", err)
		}
		if tk, found := tkMgr.GetTask(basicTask.Name); found {
			t.Error("RemoveTask() task note removed:", tk)
		}
	})
}
