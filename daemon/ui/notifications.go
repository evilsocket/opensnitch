package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/firewall"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon/monitor"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/tasks/base"
	"github.com/evilsocket/opensnitch/daemon/tasks/nodemonitor"
	"github.com/evilsocket/opensnitch/daemon/tasks/pidmonitor"
	"github.com/evilsocket/opensnitch/daemon/tasks/socketsmonitor"
	"github.com/evilsocket/opensnitch/daemon/ui/config"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"golang.org/x/net/context"
)

// NewReply constructs a new protocol notification reply
func NewReply(rID uint64, replyCode protocol.NotificationReplyCode, data string) *protocol.NotificationReply {
	return &protocol.NotificationReply{
		Id:   rID,
		Code: replyCode,
		Data: data,
	}
}

func (c *Client) getClientConfig() *protocol.ClientConfig {
	raw, _ := ioutil.ReadFile(configFile)
	nodeName := core.GetHostname()
	nodeVersion := core.GetKernelVersion()
	var ts time.Time
	rulesTotal := len(c.rules.GetAll())
	ruleList := make([]*protocol.Rule, rulesTotal)
	idx := 0
	for _, r := range c.rules.GetAll() {
		ruleList[idx] = r.Serialize()
		idx++
	}
	sysfw, err := firewall.Serialize()
	if err != nil {
		log.Warning("firewall.Serialize() error: %s", err)
	}
	return &protocol.ClientConfig{
		Id:                uint64(ts.UnixNano()),
		Name:              nodeName,
		Version:           nodeVersion,
		IsFirewallRunning: firewall.IsRunning(),
		Config:            strings.Replace(string(raw), "\n", "", -1),
		LogLevel:          uint32(log.MinLevel),
		Rules:             ruleList,
		SystemFirewall:    sysfw,
	}
}

func (c *Client) handleActionChangeConfig(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	log.Info("[notification] Reloading configuration")
	// Parse received configuration first, to get the new proc monitor method.
	newConf, err := config.Parse(ntf.Data)
	if err != nil {
		log.Warning("[notification] error parsing received config: %v", ntf.Data)
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
		return
	}

	if err := c.reloadConfiguration(true, &newConf); err != nil {
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err.Msg)
		return
	}

	// this save operation triggers a regular re-loadConfiguration()
	err = config.Save(configFile, ntf.Data)
	if err != nil {
		log.Warning("[notification] CHANGE_CONFIG not applied %s", err)
	}

	c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
}

func (c *Client) handleActionEnableRule(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	var err error
	for _, rul := range ntf.Rules {
		log.Info("[notification] enable rule: %s", rul.Name)
		// protocol.Rule(protobuf) != rule.Rule(json)
		r, _ := rule.Deserialize(rul)
		r.Enabled = true
		// save to disk only if the duration is rule.Always
		err = c.rules.Replace(r, r.Duration == rule.Always)
	}
	c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
}

func (c *Client) handleActionDisableRule(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	var err error
	for _, rul := range ntf.Rules {
		log.Info("[notification] disable rule: %s", rul)
		r, _ := rule.Deserialize(rul)
		r.Enabled = false
		err = c.rules.Replace(r, r.Duration == rule.Always)
	}
	c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
}

func (c *Client) handleActionChangeRule(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	var rErr error
	for _, rul := range ntf.Rules {
		r, err := rule.Deserialize(rul)
		if r == nil {
			rErr = fmt.Errorf("Invalid rule, %s", err)
			continue
		}
		log.Info("[notification] change rule: %s %d", r, ntf.Id)
		if err := c.rules.Replace(r, r.Duration == rule.Always); err != nil {
			log.Warning("[notification] Error changing rule: %s %s", err, r)
			rErr = err
		}
	}
	c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", rErr)
}

func (c *Client) handleActionDeleteRule(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	var err error
	for _, rul := range ntf.Rules {
		log.Info("[notification] delete rule: %s %d", rul.Name, ntf.Id)
		err = c.rules.Delete(rul.Name)
		if err != nil {
			log.Error("[notification] Error deleting rule: %s %s", err, rul)
		}
	}
	c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
}

func (c *Client) handleActionTaskStart(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	var taskConf base.TaskNotification
	err := json.Unmarshal([]byte(ntf.Data), &taskConf)
	if err != nil {
		log.Error("parsing TaskStart, err: %s, %s", err, ntf.Data)
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
		return
	}
	switch taskConf.Name {
	//case downloader.Name:
	// save to disk
	//  - c.sendNotifReply(ok - nook)
	case pidmonitor.Name:
		conf, ok := taskConf.Data.(map[string]interface{})
		if !ok {
			log.Error("[pidmon] TaskStart.Data, PID err (string expected): %v", taskConf)
			return
		}
		pid, err := strconv.Atoi(conf["pid"].(string))
		if err != nil {
			log.Error("[pidmon] TaskStart.Data, PID err: %s, %v", err, taskConf)
			c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
			return
		}
		interval, _ := conf["interval"].(string)
		c.monitorProcessDetails(pid, interval, stream, ntf)
	case nodemonitor.Name:
		conf, ok := taskConf.Data.(map[string]interface{})
		if !ok {
			log.Error("[nodemon] TaskStart.Data, \"node\" err (string expected): %v", taskConf)
			return
		}
		c.monitorNode(conf["node"].(string), conf["interval"].(string), stream, ntf)
	case socketsmonitor.Name:
		c.monitorSockets(taskConf.Data, stream, ntf)
	default:
		log.Debug("TaskStart, unknown task: %v", taskConf)
		//c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
	}
}

func (c *Client) handleActionTaskStop(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	var taskConf base.TaskNotification
	err := json.Unmarshal([]byte(ntf.Data), &taskConf)
	if err != nil {
		log.Error("parsing TaskStop, err: %s, %s", err, ntf.Data)
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", fmt.Errorf("Error stopping task: %s", ntf.Data))
		return
	}
	switch taskConf.Name {
	case pidmonitor.Name:
		conf, ok := taskConf.Data.(map[string]interface{})
		if !ok {
			log.Error("[pidmon] TaskStop.Data, PID err (string expected): %v", taskConf)
			return
		}
		pid, err := strconv.Atoi(conf["pid"].(string))
		if err != nil {
			log.Error("TaskStop.Data, err: %s, %s, %v+, %q", err, ntf.Data, taskConf.Data, taskConf.Data)
			c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
			return
		}
		TaskMgr.RemoveTask(fmt.Sprint(taskConf.Name, "-", pid))

	case nodemonitor.Name:
		conf, ok := taskConf.Data.(map[string]interface{})
		if !ok {
			log.Error("[pidmon] TaskStop.Data, PID err (string expected): %v", taskConf)
			return
		}
		TaskMgr.RemoveTask(fmt.Sprint(nodemonitor.Name, "-", conf["node"].(string)))

	case socketsmonitor.Name:
		TaskMgr.RemoveTask(socketsmonitor.Name)

	default:
		log.Debug("TaskStop, unknown task: %v", taskConf)
		//c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
	}
}

func (c *Client) handleActionEnableInterception(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	log.Info("[notification] starting interception")
	if err := monitor.ReconfigureMonitorMethod(c.config.ProcMonitorMethod, c.config.Ebpf, c.config.Audit); err != nil && err.What > monitor.NoError {
		log.Warning("[notification] error enabling monitor (%s): %s", c.config.ProcMonitorMethod, err.Msg)
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err.Msg)
		return
	}
	if err := firewall.EnableInterception(); err != nil {
		log.Warning("[notification] firewall.EnableInterception() error: %s", err)
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
		return
	}
	c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", nil)
}

func (c *Client) handleActionDisableInterception(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	log.Info("[notification] stopping interception")
	monitor.End()
	if err := firewall.DisableInterception(); err != nil {
		log.Warning("firewall.DisableInterception() error: %s", err)
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", err)
		return
	}
	c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", nil)
}

func (c *Client) handleActionReloadFw(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	log.Info("[notification] reloading firewall")

	sysfw, err := firewall.Deserialize(ntf.SysFirewall)
	if err != nil {
		log.Warning("firewall.Deserialize() error: %s", err)
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", fmt.Errorf("Error reloading firewall, invalid rules"))
		return
	}
	if err := firewall.SaveConfiguration(sysfw); err != nil {
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", fmt.Errorf("Error saving system firewall rules: %s", err))
		return
	}
	// TODO:
	// - add new API endpoints to delete, add or change rules atomically.
	// - a global goroutine where errors can be sent to the server (GUI).
	go func(c *Client) {
		var errors string
		for {
			select {
			case fwerr := <-firewall.ErrorsChan():
				errors = fmt.Sprint(errors, fwerr, ",")
				if firewall.ErrChanEmpty() {
					goto ExitWithError
				}

			// FIXME: can this operation last longer than 2s? if there're more than.. 100...10000 rules?
			case <-time.After(2 * time.Second):
				log.Debug("[notification] reload firewall. timeout fired, no errors?")
				c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", nil)
				goto Exit

			}
		}
	ExitWithError:
		c.sendNotificationReply(stream, ntf.Type, ntf.Id, "", fmt.Errorf("%s", errors))
	Exit:
	}(c)

}

func (c *Client) handleNotification(stream protocol.UI_NotificationsClient, ntf *protocol.Notification) {
	switch {
	case ntf.Type == protocol.Action_TASK_START:
		c.handleActionTaskStart(stream, ntf)

	case ntf.Type == protocol.Action_TASK_STOP:
		c.handleActionTaskStop(stream, ntf)

	case ntf.Type == protocol.Action_CHANGE_CONFIG:
		c.handleActionChangeConfig(stream, ntf)

	case ntf.Type == protocol.Action_ENABLE_INTERCEPTION:
		c.handleActionEnableInterception(stream, ntf)

	case ntf.Type == protocol.Action_DISABLE_INTERCEPTION:
		c.handleActionDisableInterception(stream, ntf)

	case ntf.Type == protocol.Action_RELOAD_FW_RULES:
		c.handleActionReloadFw(stream, ntf)

	// ENABLE_RULE just replaces the rule on disk
	case ntf.Type == protocol.Action_ENABLE_RULE:
		c.handleActionEnableRule(stream, ntf)

	case ntf.Type == protocol.Action_DISABLE_RULE:
		c.handleActionDisableRule(stream, ntf)

	case ntf.Type == protocol.Action_DELETE_RULE:
		c.handleActionDeleteRule(stream, ntf)

	// CHANGE_RULE can add() or replace() an existing rule.
	case ntf.Type == protocol.Action_CHANGE_RULE:
		c.handleActionChangeRule(stream, ntf)
	}
}

func (c *Client) sendNotificationReply(stream protocol.UI_NotificationsClient, nType protocol.Action, nID uint64, data string, err error) error {
	reply := NewReply(nID, protocol.NotificationReplyCode_OK, data)
	if err != nil {
		reply.Code = protocol.NotificationReplyCode_ERROR
		reply.Data = fmt.Sprint(err)
	}
	if err := stream.Send(reply); err != nil {
		log.Error("Error replying to notification, type: %d, id: %d, err: %s", nType, reply.Id, err)
		return err
	}

	return nil
}

// Subscribe opens a connection with the server (UI), to start
// receiving notifications.
// It firstly sends the daemon status and configuration.
func (c *Client) Subscribe() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	clientCfg, err := c.client.Subscribe(ctx, c.getClientConfig())
	if err != nil {
		log.Error("Subscribing to GUI %s", err)
		// When connecting to the GUI via TCP, sometimes the notifications channel is
		// not established, and the main channel is never closed.
		// We need to disconnect everything after a timeout and try it again.
		c.disconnect()
		return
	}

	if tempConf, err := config.Parse(clientCfg.Config); err == nil {
		c.Lock()
		clientConnectedRule.Action = rule.Action(tempConf.DefaultAction)
		c.Unlock()
	}
	c.listenForNotifications()
}

// Notifications is the channel where the daemon receives messages from the server.
// It consists of 2 grpc streams (send/receive) that are never closed,
// this way we can share messages in realtime.
// If the GUI is closed, we'll receive an error reading from the channel.
func (c *Client) listenForNotifications() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var err error
	// open the stream channel
	streamReply := &protocol.NotificationReply{Id: 0, Code: protocol.NotificationReplyCode_OK}
	c.Lock()
	c.streamNotifications, err = c.client.Notifications(ctx)
	c.Unlock()
	if err != nil {
		log.Error("establishing notifications channel %s", err)
		return
	}
	// send the first notification
	if err := c.streamNotifications.Send(streamReply); err != nil {
		log.Error("sending notification HELLO %s", err)
		return
	}
	log.Info("Start receiving notifications")
	for {
		select {
		case <-c.clientCtx.Done():
			goto Exit
		default:
			ntf, err := c.streamNotifications.Recv()
			if err == io.EOF {
				log.Warning("notification channel closed by the server")
				goto Exit
			}
			if err != nil {
				log.Error("getting notifications: %s %s", err, ntf)
				goto Exit
			}
			if ntf.Type <= protocol.Action_NONE {
				log.Debug("Server ordered to close notifications")
				goto Exit
			}
			c.handleNotification(c.streamNotifications, ntf)
		}
	}
Exit:
	c.streamNotifications.CloseSend()
	log.Info("Stop receiving notifications")
	c.disconnect()
	if TaskMgr != nil {
		TaskMgr.StopTempTasks()
	}
}
