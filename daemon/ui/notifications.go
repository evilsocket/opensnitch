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
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"golang.org/x/net/context"
)

var stopMonitoringProcess = make(chan int)

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
	return &protocol.ClientConfig{
		Id:                uint64(ts.UnixNano()),
		Name:              nodeName,
		Version:           nodeVersion,
		IsFirewallRunning: firewall.IsRunning(),
		Config:            strings.Replace(string(raw), "\n", "", -1),
		LogLevel:          uint32(log.MinLevel),
		Rules:             ruleList,
	}
}

func (c *Client) monitorProcessDetails(pid int, stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	p := procmon.NewProcess(pid, "")
	ticker := time.NewTicker(2 * time.Second)

	for {
		select {
		case _pid := <-stopMonitoringProcess:
			if _pid != pid {
				continue
			}
			goto Exit
		case <-ticker.C:
			if err := p.GetInfo(); err != nil {
				c.sendNotificationReply(stream, notification.Id, notification.Data, err)
				goto Exit
			}

			pJSON, err := json.Marshal(p)
			notification.Data = string(pJSON)
			if errs := c.sendNotificationReply(stream, notification.Id, notification.Data, err); errs != nil {
				goto Exit
			}
		}
	}

Exit:
	ticker.Stop()
}

func (c *Client) handleActionChangeConfig(stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	log.Info("[notification] Reloading configuration")
	// Parse received configuration first, to get the new proc monitor method.
	newConf, err := c.parseConf(notification.Data)
	if err != nil {
		log.Warning("[notification] error parsing received config: %v", notification.Data)
		c.sendNotificationReply(stream, notification.Id, "", err)
		return
	}

	// check if the current monitor method is different from the one received.
	// in such case close the current method, and start the new one.
	procMonitorEqual := c.isProcMonitorEqual(newConf.ProcMonitorMethod)
	if procMonitorEqual == false {
		procmon.End()
	}

	// this save operation triggers a re-loadConfiguration()
	err = c.saveConfiguration(notification.Data)
	if err != nil {
		log.Warning("[notification] CHANGE_CONFIG not applied %s", err)
	} else if err == nil && procMonitorEqual == false {
		procmon.Init()
	}

	c.sendNotificationReply(stream, notification.Id, "", err)
}

func (c *Client) handleActionEnableRule(stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	var err error
	for _, rul := range notification.Rules {
		log.Info("[notification] enable rule: %s", rul.Name)
		// protocol.Rule(protobuf) != rule.Rule(json)
		r, _ := rule.Deserialize(rul)
		r.Enabled = true
		// save to disk only if the duration is rule.Always
		err = c.rules.Replace(r, r.Duration == rule.Always)
	}
	c.sendNotificationReply(stream, notification.Id, "", err)
}

func (c *Client) handleActionDisableRule(stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	var err error
	for _, rul := range notification.Rules {
		log.Info("[notification] disable rule: %s", rul)
		r, _ := rule.Deserialize(rul)
		r.Enabled = false
		err = c.rules.Replace(r, r.Duration == rule.Always)
	}
	c.sendNotificationReply(stream, notification.Id, "", err)
}

func (c *Client) handleActionChangeRule(stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	var rErr error
	for _, rul := range notification.Rules {
		r, err := rule.Deserialize(rul)
		if r == nil {
			rErr = fmt.Errorf("Invalid rule, %s", err)
			continue
		}
		log.Info("[notification] change rule: %s %d", r, notification.Id)
		if err := c.rules.Replace(r, r.Duration == rule.Always); err != nil {
			log.Warning("[notification] Error changing rule: %s %s", err, r)
			rErr = err
		}
	}
	c.sendNotificationReply(stream, notification.Id, "", rErr)
}

func (c *Client) handleActionDeleteRule(stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	var err error
	for _, rul := range notification.Rules {
		log.Info("[notification] delete rule: %s %d", rul.Name, notification.Id)
		err = c.rules.Delete(rul.Name)
		if err != nil {
			log.Error("[notification] Error deleting rule: %s %s", err, rul)
		}
	}
	c.sendNotificationReply(stream, notification.Id, "", err)
}

func (c *Client) handleActionMonitorProcess(stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	pid, err := strconv.Atoi(notification.Data)
	if err != nil {
		log.Error("parsing PID to monitor")
		return
	}
	if !core.Exists(fmt.Sprint("/proc/", pid)) {
		c.sendNotificationReply(stream, notification.Id, "", fmt.Errorf("The process is no longer running"))
		return
	}
	go c.monitorProcessDetails(pid, stream, notification)
}

func (c *Client) handleActionStopMonitorProcess(stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	pid, err := strconv.Atoi(notification.Data)
	if err != nil {
		log.Error("parsing PID to stop monitor")
		c.sendNotificationReply(stream, notification.Id, "", fmt.Errorf("Error stopping monitor: %s", notification.Data))
		return
	}
	stopMonitoringProcess <- pid
	c.sendNotificationReply(stream, notification.Id, "", nil)
}

func (c *Client) handleNotification(stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	switch {
	case notification.Type == protocol.Action_MONITOR_PROCESS:
		c.handleActionMonitorProcess(stream, notification)

	case notification.Type == protocol.Action_STOP_MONITOR_PROCESS:
		c.handleActionStopMonitorProcess(stream, notification)

	case notification.Type == protocol.Action_CHANGE_CONFIG:
		c.handleActionChangeConfig(stream, notification)

	case notification.Type == protocol.Action_LOAD_FIREWALL:
		log.Info("[notification] starting firewall")
		firewall.Init(nil)
		c.sendNotificationReply(stream, notification.Id, "", nil)

	case notification.Type == protocol.Action_UNLOAD_FIREWALL:
		log.Info("[notification] stopping firewall")
		firewall.Stop(nil)
		c.sendNotificationReply(stream, notification.Id, "", nil)

	// ENABLE_RULE just replaces the rule on disk
	case notification.Type == protocol.Action_ENABLE_RULE:
		c.handleActionEnableRule(stream, notification)

	case notification.Type == protocol.Action_DISABLE_RULE:
		c.handleActionDisableRule(stream, notification)

	case notification.Type == protocol.Action_DELETE_RULE:
		c.handleActionDeleteRule(stream, notification)

	// CHANGE_RULE can add() or replace) an existing rule.
	case notification.Type == protocol.Action_CHANGE_RULE:
		c.handleActionChangeRule(stream, notification)
	}
}

func (c *Client) sendNotificationReply(stream protocol.UI_NotificationsClient, nID uint64, data string, err error) error {
	reply := NewReply(nID, protocol.NotificationReplyCode_OK, data)
	if err != nil {
		reply.Code = protocol.NotificationReplyCode_ERROR
		reply.Data = fmt.Sprint(err)
	}
	if err := stream.Send(reply); err != nil {
		log.Error("Error replying to notification: %s %d", err, reply.Id)
		return err
	}

	return nil
}

// Subscribe opens a connection with the server (UI), to start
// receiving notifications.
// It firstly sends the daemon status and configuration.
func (c *Client) Subscribe() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := c.client.Subscribe(ctx, c.getClientConfig()); err != nil {
		log.Error("Subscribing to GUI %s", err)
		return
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

	// open the stream channel
	streamReply := &protocol.NotificationReply{Id: 0, Code: protocol.NotificationReplyCode_OK}
	notisStream, err := c.client.Notifications(ctx)
	if err != nil {
		log.Error("establishing notifications channel %s", err)
		return
	}
	// send the first notification
	if err := notisStream.Send(streamReply); err != nil {
		log.Error("sending notification HELLO %s", err)
		return
	}
	log.Info("Start receiving notifications")
	for {
		select {
		case <-c.clientCtx.Done():
			goto Exit
		default:
			noti, err := notisStream.Recv()
			if err == io.EOF {
				log.Warning("notification channel closed by the server")
				goto Exit
			}
			if err != nil {
				log.Error("getting notifications: %s %s", err, noti)
				goto Exit
			}
			c.handleNotification(notisStream, noti)
		}
	}
Exit:
	notisStream.CloseSend()
	log.Info("Stop receiving notifications")
}
