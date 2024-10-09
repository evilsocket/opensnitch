package ui

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/tasks/nodemonitor"
	"github.com/evilsocket/opensnitch/daemon/tasks/pidmonitor"
	"github.com/evilsocket/opensnitch/daemon/tasks/socketsmonitor"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"golang.org/x/net/context"
)

func (c *Client) monitorSockets(config interface{}, stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	sockMonTask, err := socketsmonitor.New(config, true)
	if err != nil {
		c.sendNotificationReply(stream, notification.Id, "", err)
		return
	}
	ctxSock, err := TaskMgr.AddTask(socketsmonitor.Name, sockMonTask)
	if err != nil {
		c.sendNotificationReply(stream, notification.Id, "", err)
		return
	}
	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				goto Exit
			case err := <-sockMonTask.Errors():
				c.sendNotificationReply(stream, notification.Id, "", err)
			case temp := <-sockMonTask.Results():
				data, ok := temp.(string)
				if !ok {
					goto Exit
				}
				c.sendNotificationReply(stream, notification.Id, data, nil)
			}
		}
	Exit:
		// task should have already been removed via TASK_STOP
	}(ctxSock)
}

func (c *Client) monitorNode(node, interval string, stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	taskName, nodeMonTask := nodemonitor.New(node, interval, true)
	ctxNode, err := TaskMgr.AddTask(taskName, nodeMonTask)
	if err != nil {
		c.sendNotificationReply(stream, notification.Id, "", err)
		return
	}
	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				goto Exit
			case err := <-nodeMonTask.Errors():
				c.sendNotificationReply(stream, notification.Id, "", err)
			case temp := <-nodeMonTask.Results():
				data, ok := temp.(string)
				if !ok {
					goto Exit
				}
				c.sendNotificationReply(stream, notification.Id, data, nil)
			}
		}
	Exit:
		TaskMgr.RemoveTask(taskName)
	}(ctxNode)
}

func (c *Client) monitorProcessDetails(pid int, interval string, stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	if !core.Exists(fmt.Sprint("/proc/", pid)) {
		c.sendNotificationReply(stream, notification.Id, "", fmt.Errorf("The process is no longer running"))
		return
	}

	taskName, pidMonTask := pidmonitor.New(pid, interval, true)
	ctx, err := TaskMgr.AddTask(taskName, pidMonTask)
	if err != nil {
		c.sendNotificationReply(stream, notification.Id, "", err)
		return
	}
	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				goto Exit
			case err := <-pidMonTask.Errors():
				c.sendNotificationReply(stream, notification.Id, "", err)
			case temp := <-pidMonTask.Results():
				data, ok := temp.(string)
				if !ok {
					goto Exit
				}
				c.sendNotificationReply(stream, notification.Id, data, nil)
			}
		}
	Exit:
		TaskMgr.RemoveTask(taskName)
	}(ctx)

}
