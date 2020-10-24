package ui

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/core"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/firewall"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/procmon"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/rule"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/ui/protocol"
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

func (c *Client) handleNotification(stream protocol.UI_NotificationsClient, notification *protocol.Notification) {
	switch {
	case notification.Type == protocol.Action_CHANGE_CONFIG:
		log.Info("[notification] Reloading configuration")
		// Parse receid configuration first, to get the new proc monitor method.
		newConf, err := c.parseConf(notification.Data)
		if err != nil {
			log.Warning("[notification] error parsing received config: %v", notification.Data)
			c.sendNotificationReply(stream, notification.Id, err)
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
			log.Warning("[notification] CHANGE_CONFIG not applied", err)
		} else if err == nil && procMonitorEqual == false {
			procmon.Init()
		}

		c.sendNotificationReply(stream, notification.Id, err)

	case notification.Type == protocol.Action_LOAD_FIREWALL:
		log.Info("[notification] starting firewall")
		firewall.Init(nil)
		c.sendNotificationReply(stream, notification.Id, nil)

	case notification.Type == protocol.Action_UNLOAD_FIREWALL:
		log.Info("[notification] stopping firewall")
		firewall.Stop(nil)
		c.sendNotificationReply(stream, notification.Id, nil)

	// ENABLE_RULE just replaces the rule on disk
	case notification.Type == protocol.Action_ENABLE_RULE:
		var rErr error
		for _, rul := range notification.Rules {
			log.Info("[notification] enable rule: ", rul.Name)
			// protocol.Rule(protobuf) != rule.Rule(json)
			r, _ := rule.Deserialize(rul)
			r.Enabled = true
			// save to disk only if the duration is rule.Always
			if err := c.rules.Replace(r, r.Duration == rule.Always); err != nil {
				rErr = err
			}
		}
		c.sendNotificationReply(stream, notification.Id, rErr)

	case notification.Type == protocol.Action_DISABLE_RULE:
		var rErr error
		for _, rul := range notification.Rules {
			log.Info("[notification] disable: ", rul)
			r, _ := rule.Deserialize(rul)
			r.Enabled = false
			if err := c.rules.Replace(r, r.Duration == rule.Always); err != nil {
				rErr = err
			}
		}
		c.sendNotificationReply(stream, notification.Id, rErr)

	case notification.Type == protocol.Action_DELETE_RULE:
		var rErr error
		for _, rul := range notification.Rules {
			log.Info("[notification] delete rule: ", rul.Name, notification.Id)
			if err := c.rules.Delete(rul.Name); err != nil {
				log.Error("deleting rule: ", err, rul)
				rErr = err
			}
		}
		c.sendNotificationReply(stream, notification.Id, rErr)

	// CHANGE_RULE can add() or replace) an existing rule.
	case notification.Type == protocol.Action_CHANGE_RULE:
		var rErr error
		for _, rul := range notification.Rules {
			log.Info("CHANGE_RULE: ", rul)
			r, err := rule.Deserialize(rul)
			if r == nil {
				rErr = fmt.Errorf("Invalid rule, %s", err)
				continue
			}
			log.Info("[notification] change rule: ", r, notification.Id)
			if err := c.rules.Replace(r, r.Duration == rule.Always); err != nil {
				log.Error("[notification] Error changing rule: ", err, r)
				rErr = err
			}
		}
		c.sendNotificationReply(stream, notification.Id, rErr)
	}
}

func (c *Client) sendNotificationReply(stream protocol.UI_NotificationsClient, nID uint64, err error) {
	reply := NewReply(nID, protocol.NotificationReplyCode_OK, "")
	if err != nil {
		reply.Code = protocol.NotificationReplyCode_ERROR
		reply.Data = fmt.Sprint(err)
	}
	if err := stream.Send(reply); err != nil {
		log.Error("Error replying to notification:", err, reply.Id)
	}
}

// Subscribe opens a connection with the server (UI), to start
// receiving notifications.
// It firstly sends the daemon status and configuration.
func (c *Client) Subscribe() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := c.client.Subscribe(ctx, c.getClientConfig()); err != nil {
		log.Error("Subscribing to GUI", err)
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
		log.Error("establishing notifications channel", err)
		return
	}
	// send the first notification
	if err := notisStream.Send(streamReply); err != nil {
		log.Error("sending notfication HELLO", err)
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
				log.Error("getting notifications: ", err, noti)
				goto Exit
			}
			c.handleNotification(notisStream, noti)
		}
	}
Exit:
	notisStream.CloseSend()
	log.Info("Stop receiving notifications")
}
