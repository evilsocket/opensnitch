package tasks

import (
	"context"
	"fmt"
	//"io/ioutil"
	//"strconv"
	//"encoding/json"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks/base"
	"github.com/evilsocket/opensnitch/daemon/tasks/config"
	//"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

type EventTask struct {
	Ctx    context.Context
	Cancel context.CancelFunc
	Task   base.Task
	Name   string
}

// TaskManager manages a collection of tasks.
type TaskManager struct {
	loader      *config.Loader
	Ctx         context.Context
	Cancel      context.CancelFunc
	tasks       map[string]base.Task
	TaskAdded   chan EventTask
	TaskRemoved chan EventTask

	mu sync.Mutex
}

// NewTaskManager creates a new task manager.
func NewTaskManager() *TaskManager {
	tm := &TaskManager{
		tasks:       make(map[string]base.Task),
		TaskAdded:   make(chan EventTask),
		TaskRemoved: make(chan EventTask),
	}
	loader, err := config.NewTasksLoader()
	if err != nil {
		log.Warning("NewTaskManager, unable to create the tasks loader: %s", err)
	}
	tm.loader = loader
	tm.Ctx, tm.Cancel = context.WithCancel(context.Background())

	return tm
}

// AddTask adds a new task to the task manager.
// The new task runs as a goroutine.
func (tm *TaskManager) AddTask(name string, task base.Task) (context.Context, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, ok := tm.tasks[name]; ok {
		return nil, fmt.Errorf("task with name %s already exists", name)
	}

	log.Important("[tasks] Adding task: %s", name)
	tm.tasks[name] = task
	ctx, cancel := context.WithCancel(context.Background())
	go func(ctx context.Context, cancel context.CancelFunc) {
		defer cancel()

		err := task.Start(ctx, cancel)
		if err != nil {
			log.Debug("[tasks] Failed to start task %s: %v\n", name, err)
			return
		}
		tm.TaskAdded <- EventTask{Ctx: ctx, Cancel: cancel, Task: task, Name: name}

		for {
			select {
			case <-tm.Ctx.Done():
				goto Exit
			case <-ctx.Done():
				goto Exit
			}
		}
	Exit:
		if _, found := tm.GetTask(name); found {
			log.Debug("[tasks] AddTask() stopping task %s", name)
			task.Stop()
		}

	}(ctx, cancel)

	return ctx, nil
}

// RemoveTask removes a task from the task manager.
func (tm *TaskManager) RemoveTask(name string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	log.Debug("[tasks] RemoveTask() %s", name)

	tk, ok := tm.tasks[name]
	if !ok {
		return fmt.Errorf("task with name %s does not exist", name)
	}

	tm.TaskRemoved <- EventTask{Task: tk, Name: name}
	log.Debug("[tasks] RemoveTask() stopping task %s", name)
	tk.Stop()

	delete(tm.tasks, name)
	return nil
}

// PauseAll pauses all tasks that don't need to run while the daemon is
// disconnected from the GUI (server).
// Things to take into account:
//  - The GUI may have been closed, therefore, the GUI won't have the id of the
//    paused notifications. So when we resume the tasks, the GUI won't know
//    about those notifications.
func (tm *TaskManager) PauseAll() {
	for name, task := range tm.tasks {
		log.Debug("[tasks] Pausing task %s", name)
		task.Pause()
	}
}

// ResumeAll resumes paused tasks
func (tm *TaskManager) ResumeAll() {
	for name, task := range tm.tasks {
		log.Debug("[tasks] Resuming task %s", name)
		task.Resume()
	}
}

// StopAll stops all running tasks
func (tm *TaskManager) StopAll() {
	for name := range tm.tasks {
		log.Debug("[tasks] Stopping task %s", name)
		tm.RemoveTask(name)
	}
}

// StopTempTasks stops temporary tasks.
// These tasks only live while the daemon is connected to the GUI, for real-time
// monitoring.
// Example of such tasks are: monitor PID, monitor node details, monitor listening/established connections, on-demand malware scans, ...
func (tm *TaskManager) StopTempTasks() {
	for name := range tm.tasks {
		tk, found := tm.GetTask(name)
		if !found || !tk.IsTemporary() {
			continue
		}
		log.Debug("[tasks] Stopping temporary task %s", name)

		tm.RemoveTask(name)
	}
}

// GetTask ...
func (tm *TaskManager) GetTask(name string) (tk base.Task, found bool) {
	tk, found = tm.tasks[name]
	return
}

// UpdateTask replaces and existing task, with a new one.
func (tm *TaskManager) UpdateTask(name string, task base.Task) (context.Context, error) {
	if _, found := tm.GetTask(name); !found {
		return nil, fmt.Errorf("task %s not found", name)
	}
	if err := tm.RemoveTask(name); err != nil {
		return nil, fmt.Errorf("updating task %s (remove)", name)
	}
	if err, ctx := tm.AddTask(name, task); err != nil {
		return err, ctx
	}
	return nil, fmt.Errorf("updating task %s", name)
}

// Stop stops all running tasks.
func (tm *TaskManager) Stop() {
	tm.StopAll()
	if tm.Cancel != nil {
		tm.Cancel()
	}
}
