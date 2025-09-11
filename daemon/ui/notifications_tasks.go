package ui

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks"
	//"github.com/evilsocket/opensnitch/daemon/tasks/base"
	"github.com/evilsocket/opensnitch/daemon/tasks/nodemonitor"
	"github.com/evilsocket/opensnitch/daemon/tasks/pidmonitor"
	"github.com/evilsocket/opensnitch/daemon/tasks/socketsmonitor"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"golang.org/x/net/context"
)

// monitor events of the tasks manager: new task added, removed, etc.
func (c *Client) monitorTaskManager(tm *tasks.TaskManager) {
	for {
		select {
		case <-TaskMgr.Ctx.Done():
			goto Exit
		case taskEvent := <-TaskMgr.TaskAdded:
			log.Debug("Task Added: %s", taskEvent.Name)
			go c.monitorTaskEvents(
				taskEvent.Ctx,
				c.streamNotifications,
				taskEvent.Task.GetID(),
				taskEvent.Task.Results(),
				taskEvent.Task.Errors(),
			)

		case taskEvent := <-TaskMgr.TaskRemoved:
			log.Debug("Task removed: %v", taskEvent.Name)
		}
	}
Exit:
}

// monitor events sent by the tasks.
func (c *Client) monitorTaskEvents(ctx context.Context, stream protocol.UI_NotificationsClient, notifId uint64, results <-chan interface{}, errors <-chan error) {
	postMsg := func(data string, err error) {

		// when a task is loaded frm disk, we don't have a notification ID to
		// identify this task on the UI. For these cases, we use a unique ID for
		// each task.
		// The notification ID sent from the UI is a timestamp, so we don't expect
		// low values here.
		if stream != nil && notifId > 10000 {
			c.sendNotificationReply(stream, notifId, data, err)
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
	log.Debug("[tasks] stop monitoring events %d", notifId)
}

func (c *Client) monitorSockets(config interface{}, stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	sockMonTask, err := socketsmonitor.New(socketsmonitor.Name, config, true)
	sockMonTask.SetID(notification.Id)
	if err != nil {
		c.sendNotificationReply(stream, notification.Id, "", err)
		return
	}
	_, err = TaskMgr.AddTask(sockMonTask.Name, sockMonTask)
	if err != nil {
		c.sendNotificationReply(stream, notification.Id, "", err)
		return
	}
}

func (c *Client) monitorNode(node, interval string, stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	taskName, nodeMonTask := nodemonitor.New(node, interval, true)
	nodeMonTask.SetID(notification.Id)
	_, err := TaskMgr.AddTask(taskName, nodeMonTask)
	if err != nil {
		c.sendNotificationReply(stream, notification.Id, "", err)
		return
	}
}

func (c *Client) monitorProcessDetails(pid int, interval string, stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	if !core.Exists(fmt.Sprint("/proc/", pid)) {
		c.sendNotificationReply(stream, notification.Id, "", fmt.Errorf("The process is no longer running"))
		return
	}

	taskName, pidMonTask := pidmonitor.New(pid, interval, true)
	pidMonTask.SetID(notification.Id)
	_, err := TaskMgr.AddTask(taskName, pidMonTask)
	if err != nil {
		c.sendNotificationReply(stream, notification.Id, "", err)
		return
	}
}
