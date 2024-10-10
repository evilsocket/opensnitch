package tasks

import (
	"context"
)

// TaskBase holds the common fields of every task.
// Warning: don't define fields in tasks with these names.
type TaskBase struct {
	Ctx     context.Context
	Cancel  context.CancelFunc
	Results chan interface{}
	Errors  chan error

	// Stop the task if the daemon is disconnected from the GUI (server).
	// Some tasks don't need to run if the daemon is not connected to the GUI,
	// like PIDMonitor, SocketsMonitor,etc.
	// There might be other tasks that will perform some actions, and they
	// may send a notification on finish.
	StopOnDisconnect bool
}

// Task defines the interface for tasks that the task manager will execute.
type Task interface {
	// Start starts the task, potentially running it asynchronously.
	Start(ctx context.Context, cancel context.CancelFunc) error

	// Stop stops the task.
	Stop() error

	Pause() error
	Resume() error

	// Results returns a channel that can be used to receive task results.
	Results() <-chan interface{}

	// channel used to send errors
	Errors() <-chan error
}

// TaskNotification is the data we receive when a new task is started from
// the GUI (server).
// The notification.data field will contain a string like:
// '{"name": "...", "data": {"interval": "3s", "...": ...} }'
//
// where Name is the task to start, sa defined by the Name var of each task,
// and Data is the configuration of each task (a map[string]string, converted by the json package).
type TaskNotification struct {
	// Data of the task.
	Data interface{}

	// Name of the task.
	Name string
}
