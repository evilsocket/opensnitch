package ui

import (
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/firewall"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/procmon"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/ui/protocol"
	"golang.org/x/net/context"
)

func (c *Client) getClientConfig() *protocol.ClientConfig {
	raw, _ := ioutil.ReadFile(configFile)
	nodeName, _ := ioutil.ReadFile("/proc/sys/kernel/hostname")
	nodeVersion, _ := ioutil.ReadFile("/proc/sys/kernel/version")
	var ts time.Time
	return &protocol.ClientConfig{
		Id:                uint64(ts.UnixNano()),
		Name:              strings.Replace(string(nodeName), "\n", "", -1),
		Version:           strings.Replace(string(nodeVersion), "\n", "", -1),
		IsFirewallRunning: firewall.IsRunning(),
		Config:            strings.Replace(string(raw), "\n", "", -1),
		LogLevel:          uint32(log.MinLevel),
		// TODO
		Rules: nil,
	}
}

func (c *Client) handleNotification(notification *protocol.Notification) {
	switch {
	case notification.Type == protocol.Action_CHANGE_CONFIG:
		log.Info("[notification] Reloading configuration")
		// this save operation triggers a re-loadConfiguration()
		c.saveConfiguration(notification.Data)
		// XXX: can the Reload() happen before finishing loading conf?
		procmon.Reload()
	case notification.Type == protocol.Action_LOAD_FIREWALL:
		log.Info("[notification] starting firewall")
		firewall.Init(nil)
	case notification.Type == protocol.Action_UNLOAD_FIREWALL:
		log.Info("[notification] stopping firewall")
		firewall.Stop(nil)
	}
}

// Subscribe opens a connection with the server (UI), to start
// receiving notifications.
// It firstly sends the daemon status and configuration.
func (c *Client) Subscribe() {
	log.Info("Subscribe")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notisStream, err := c.client.Notifications(ctx)
	if err != nil {
		log.Error("establishing notifications channel", err)
		return
	}
	if err := notisStream.Send(c.getClientConfig()); err != nil {
		log.Error("sending notfication HELLO", err)
		return
	}
	log.Info("Start receiving notifications")
	for {
		noti, err := notisStream.Recv()
		if err == io.EOF {
			log.Warning("notification channel closed by the server")
			break
		}
		if err != nil {
			log.Error("getting notifications: ", err, noti)
			break
		}
		c.handleNotification(noti)
		//if err := notisStream.Send(c.getNotificationConfig()); err != nil {
		//	log.Error("Error Subscribe()2 sending initial packet")
		//}
	}

	notisStream.CloseSend()
	log.Info("Stop receiving notifications")
}
