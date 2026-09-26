package ui

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks"
	taskBase "github.com/evilsocket/opensnitch/daemon/tasks/base"
	"github.com/evilsocket/opensnitch/daemon/tasks/nodemonitor"
	"github.com/evilsocket/opensnitch/daemon/tasks/pidmonitor"
	"github.com/evilsocket/opensnitch/daemon/tasks/portscanblocks"
	"github.com/evilsocket/opensnitch/daemon/tasks/socketsmonitor"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"golang.org/x/net/context"
)

// monitor events of the tasks manager: new task added, removed, etc.
// It reads the manager it is given, not the TaskMgr global: a client started
// against one manager must not take the events of another.
func (c *Client) monitorTaskManager(tm *tasks.TaskManager) {
	for {
		select {
		case <-tm.Ctx.Done():
			goto Exit
		case taskEvent := <-tm.TaskAdded:
			log.Debug("Task Added: %s", taskEvent.Name)
			go c.monitorTaskEvents(
				taskEvent.Ctx,
				taskEvent.Name,
				c.streamNotifications,
				0,
				taskEvent.Task.GetID(),
				taskEvent.Task.Results(),
				taskEvent.Task.Errors(),
			)

		case taskEvent := <-tm.TaskRemoved:
			log.Debug("Task removed: %v", taskEvent.Name)
		}
	}
Exit:
}

// monitor events sent by the tasks.
func (c *Client) monitorTaskEvents(ctx context.Context, taskName string, stream protocol.UI_NotificationsClient, ntfType protocol.Action, ntfId uint64, results <-chan interface{}, errors <-chan error) {
	postMsg := func(data string, err error) {

		// when a task is loaded from disk, we don't have a notification ID to
		// identify this task on the UI. For these cases, we use a unique ID for
		// each task.
		// The notification ID sent from the UI is a timestamp, so we don't expect
		// low values here.
		if stream != nil && ntfId > 10000 {
			c.sendNotificationReply(stream, ntfType, ntfId, data, err)
		} else {
			alertType := protocol.Alert_INFO
			if err != nil {
				alertType = protocol.Alert_ERROR
			}
			c.PostAlert(
				alertType,
				protocol.Alert_GENERIC,
				protocol.Alert_SHOW_ALERT,
				protocol.Alert_MEDIUM,
				data)
			c.loggers.Log(
				taskBase.TaskNotification{Data: data, Name: taskName},
				nil,
				nil)
		}
	}

	for {
		select {
		case <-ctx.Done():
			goto Exit
		case err := <-errors:
			postMsg("", err)

		case temp := <-results:
			data, ok := temp.(string)
			if ok {
				postMsg(data, nil)
			}
		}
	}
Exit:
	// task should have already been removed via TASK_STOP
	log.Debug("[tasks] stop monitoring events %d (%d)", ntfId, ntfType)
}

func (c *Client) monitorSockets(config interface{}, stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	sockMonTask, err := socketsmonitor.New(socketsmonitor.Name, config, true)
	sockMonTask.SetID(ntf.Id)
	if err != nil {
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
		return
	}
	_, err = TaskMgr.AddTask(sockMonTask.Name, sockMonTask)
	if err != nil {
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
		return
	}
}

func (c *Client) monitorNode(node, interval string, stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	taskName, nodeMonTask := nodemonitor.New(node, interval, true)
	nodeMonTask.SetID(ntf.Id)
	_, err := TaskMgr.AddTask(taskName, nodeMonTask)
	if err != nil {
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
		return
	}
}

func (c *Client) monitorProcessDetails(pid int, interval string, stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	if !core.Exists(fmt.Sprint("/proc/", pid)) {
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", fmt.Errorf("The process is no longer running"))
		return
	}

	taskName, pidMonTask := pidmonitor.New(pid, interval, true)
	pidMonTask.SetID(ntf.Id)
	_, err := TaskMgr.AddTask(taskName, pidMonTask)
	if err != nil {
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
		return
	}
}

// monitorPortScanBlocks starts the task that lists the blocked and detected
// scan sources.
//
// Unlike the process and socket monitors, this one can legitimately be asked
// for while its subject does not exist -- port scan detection is off by
// default -- so the refusal is reported to the GUI rather than logged. A
// view that opened onto an empty table would say "nothing is blocked" when
// the truth is "nothing is watching".
func (c *Client) monitorPortScanBlocks(config interface{}, stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	if c.portScanResponder() == nil {
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "",
			fmt.Errorf("port scan detection is not running"))
		return
	}
	task, err := portscanblocks.New(portScanLister{c: c}, config, true)
	if err != nil {
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
		return
	}
	task.SetID(ntf.Id)
	if _, err := TaskMgr.AddTask(portscanblocks.Name, task); err != nil {
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
		return
	}
}

// portScanLister reads the block table through the client, once per snapshot.
//
// It deliberately does not capture the responder. Detection can be stopped, or
// torn down and rebuilt by a configuration reload, while the list is on screen:
// a captured monitor would go on answering from a block table nobody expires
// any more, so the GUI would show addresses as blocked after the rules were
// gone. Reading it each time means the task follows the daemon.
type portScanLister struct{ c *Client }

// BlockedList implements portscanblocks.Lister.
func (l portScanLister) BlockedList(limit int) ([]portscanblocks.Blocked, int, error) {
	r := l.c.portScanResponder()
	if r == nil {
		return nil, 0, fmt.Errorf("port scan detection is not running")
	}
	list, total := r.BlockedList(limit)
	return list, total, nil
}

// DetectionList implements portscanblocks.DetectionLister.
func (l portScanLister) DetectionList(limit int) ([]portscanblocks.Detected, int, bool, error) {
	r := l.c.portScanResponder()
	if r == nil {
		return nil, 0, false, fmt.Errorf("port scan detection is not running")
	}
	list, total, canBlock := r.DetectionList(limit)
	return list, total, canBlock, nil
}
