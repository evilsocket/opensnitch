package tasks

import (
	"context"
	"fmt"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/log"
)

// TaskManager manages a collection of tasks.
type TaskManager struct {
	tasks    map[string]Task
	stopChan chan struct{}
	mu       sync.Mutex
}

// NewTaskManager creates a new task manager.
func NewTaskManager() *TaskManager {
	return &TaskManager{
		tasks:    make(map[string]Task),
		stopChan: make(chan struct{}),
	}
}

// AddTask adds a new task to the task manager.
func (tm *TaskManager) AddTask(name string, task Task) (context.Context, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, ok := tm.tasks[name]; ok {
		return nil, fmt.Errorf("task with name %s already exists", name)
	}

	tm.tasks[name] = task
	ctx, cancel := context.WithCancel(context.Background())
	go func(ctx context.Context, cancel context.CancelFunc) {
		defer cancel()

		err := task.Start(ctx, cancel)
		if err != nil {
			log.Debug("Failed to start task %s: %v\n", name, err)
			return
		}

		select {
		case <-tm.stopChan:
			task.Stop()
		case <-ctx.Done():
			return
		}
	}(ctx, cancel)

	return ctx, nil
}

// PauseAll pauses all tasks that don't need to run while the daemon is
// disconnected from the GUI (server).
// Things to take into account:
//  - The GUI may have been closed, therefore, the GUI won't have the id of the
//    paused notifications. So when we resume the tasks, the GUI won't know
//    about those notifications.
func (tm *TaskManager) PauseAll() {
	for name, task := range tm.tasks {
		log.Debug("taskManager. Pausing task %s", name)
		task.Pause()
	}
}

// ResumeAll resumes paused tasks
func (tm *TaskManager) ResumeAll() {
	for name, task := range tm.tasks {
		log.Debug("taskManager. Resuming task %s", name)
		task.Resume()
	}
}

// StopAll stops all running tasks
// TODO: stop only tasks with a TTL while it's connected to the GUI (server)
// example of such tasks are: monitor PID, monitor node details, monitor listening/established connections, on-demand scan, ...
func (tm *TaskManager) StopAll() {
	for name := range tm.tasks {
		log.Debug("taskManager. Stopping task %s", name)
		tm.RemoveTask(name)
	}
}

// GetTask ...
func (tm *TaskManager) GetTask(name string) (tk Task, found bool) {
	tk, found = tm.tasks[name]
	return
}

// UpdateTask replaces and existing task, with a new one.
func (tm *TaskManager) UpdateTask(name string, task Task) (context.Context, error) {
	if _, found := tm.GetTask(name); !found {
		return nil, fmt.Errorf("task %s not found", name)
	}
	if err := tm.RemoveTask(name); err != nil {
		return nil, fmt.Errorf("Error updating task %s (remove)", name)
	}
	if err, ctx := tm.AddTask(name, task); err != nil {
		return err, ctx
	}
	return nil, fmt.Errorf("Error updating task %s", name)
}

// RemoveTask removes a task from the task manager.
func (tm *TaskManager) RemoveTask(name string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tk, ok := tm.tasks[name]
	if !ok {
		return fmt.Errorf("task with name %s does not exist", name)
	}
	tk.Stop()

	delete(tm.tasks, name)
	return nil
}

// Stop stops all running tasks.
func (tm *TaskManager) Stop() {
	close(tm.stopChan)
}
