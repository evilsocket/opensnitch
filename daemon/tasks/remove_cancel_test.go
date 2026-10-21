package tasks_test

import (
	"context"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/tasks"
	"github.com/evilsocket/opensnitch/daemon/tasks/base"
)

type fakeTask struct {
	base.TaskBase
	results chan interface{}
	errs    chan error
}

func (f *fakeTask) Start(ctx context.Context, cancel context.CancelFunc) error { return nil }
func (f *fakeTask) Stop() error                                                { return nil }
func (f *fakeTask) Pause() error                                               { return nil }
func (f *fakeTask) Resume() error                                              { return nil }
func (f *fakeTask) Results() <-chan interface{}                                { return f.results }
func (f *fakeTask) Errors() <-chan error                                       { return f.errs }

// RemoveTask must cancel the context AddTask created, so the task's goroutine
// ends with the task instead of lingering until the whole manager stops.
func TestRemoveTaskCancelsTheTaskContext(t *testing.T) {
	tm := tasks.NewTaskManager()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-tm.TaskAdded:
			case <-tm.TaskRemoved:
			case <-done:
				return
			}
		}
	}()

	ctx, err := tm.AddTask("t", &fakeTask{results: make(chan interface{}), errs: make(chan error)})
	if err != nil {
		t.Fatalf("AddTask: %v", err)
	}
	if err := tm.RemoveTask("t"); err != nil {
		t.Fatalf("RemoveTask: %v", err)
	}

	select {
	case <-ctx.Done():
		// cancelled, as it should be
	case <-time.After(2 * time.Second):
		t.Fatal("RemoveTask did not cancel the task context")
	}
}
