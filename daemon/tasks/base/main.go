package base

import (
	"context"
)

const (
	PID_MON      = 9000
	NODE_MON     = 9001
	SOCKETS_MON  = 9002
	DOWNLOADER   = 9003
	NETSNIFFER   = 9004
	IOCS_SCANNER = 9005
	REDFLAGS     = 9006
)

// TaskBase holds the common fields of every task.
// Warning: don't define fields in tasks with these names.
type TaskBase struct {
	Ctx     context.Context
	Cancel  context.CancelFunc
	Name    string
	Results chan interface{}
	Errors  chan error

	// ID that identifies this task
	// Temporary tasks like PIDMonitor have a NotificationID which is used
	// to receive and display the data from the task on the GUI.
	// Permanent tasks like a background downloader won't have this ID,
	// so this ID will serve as initial identification to know who is sending what,
	// and treat data apropiately, if needed (sometimes it'll just be a desktop notification).
	ID uint64

	// Stop the task if the daemon is disconnected from the GUI (server).
	// Some tasks don't need to run if the daemon is not connected to the GUI,
	// like PIDMonitor, SocketsMonitor,etc.
	// There might be other tasks that will perform some actions, and they
	// may send a notification on finish.
	StopOnDisconnect bool

	stopped bool
}

func (t *TaskBase) SetID(id uint64) {
	t.ID = id
}

func (t *TaskBase) GetID() uint64 {
	return t.ID
}

func (t *TaskBase) IsTemporary() bool {
	return t.StopOnDisconnect
}

type TaskResults struct {
	Type int
	Data interface{}
}

// Task defines the interface for tasks that the task manager will execute.
type Task interface {
	// Start starts the task, potentially running it asynchronously.
	Start(ctx context.Context, cancel context.CancelFunc) error

	// Stop stops the task.
	Stop() error

	SetID(uint64)
	GetID() uint64
	IsTemporary() bool

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
