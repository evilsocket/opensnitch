package api

import (
	"sync"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/ui/protocol"
	"github.com/gustavo-iniguez-goya/opensnitch/server/api/nodes"
	"golang.org/x/net/context"
)

// Client struct groups the API functionality to communicate with the nodes
type Client struct {
	Lock         sync.RWMutex
	lastStats    *protocol.Statistics
	nodesChan    chan bool
	rulesInChan  chan *protocol.Connection
	rulesOutChan chan *protocol.Rule
}

// rules related constants
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"

	RuleSimple = "simple"
	RuleList   = "list"
	RuleRegexp = "regexp"

	RuleOnce    = "once"
	Rule15s     = "15s"
	Rule30s     = "30s"
	Rule5m      = "5m"
	Rule1h      = "1h"
	RuleRestart = "until restart"
	RuleAlways  = "always"

	FilterByPath    = "process.path"
	FilterByCommand = "process.command"
	FilterByUserID  = "user.id"
	FilterByDstIP   = "dest.ip"
	FilterByDstPort = "dest.port"
	FilterByDstHost = "dest.host"
)

// NewClient setups a new client and starts the server to listen for new nodes.
func NewClient(serverProto, serverPort string) *Client {
	c := &Client{
		nodesChan:    make(chan bool),
		rulesInChan:  make(chan *protocol.Connection, 1),
		rulesOutChan: make(chan *protocol.Rule, 1),
	}
	go startServer(c, serverProto, serverPort)
	return c
}

// UpdateStats save latest stats received from a node.
func (c *Client) UpdateStats(ctx context.Context, stats *protocol.Statistics) {
	if stats == nil {
		return
	}
	c.Lock.Lock()
	defer c.Lock.Unlock()
	c.lastStats = stats
	nodes.UpdateStats(ctx, stats)
}

// GetLastStats returns latest stasts from a node.
func (c *Client) GetLastStats() *protocol.Statistics {
	c.Lock.RLock()
	defer c.Lock.RUnlock()

	// TODO: return last stats for a given node
	return c.lastStats
}

// AskRule sends the connection details through a channel.
// A client must consume data on that channel, and send the response via the
// rulesOutChan channel.
func (c *Client) AskRule(con *protocol.Connection) chan *protocol.Rule {
	c.rulesInChan <- con
	return c.rulesOutChan
}

// AddNewNode adds a new node to the list of connected nodes.
func (c *Client) AddNewNode(ctx context.Context, nodeConf *protocol.ClientConfig) {
	log.Info("AddNewNode: %s - %s, %v", nodeConf.Name, nodeConf.Version)
	nodes.Add(ctx, nodeConf)
	c.nodesChan <- true
}

// OpenChannelWithNode updates the node with the streaming channel.
// This channel is used to send notifications to the nodes (change debug level,
// stop/start interception, etc).
func (c *Client) OpenChannelWithNode(notificationsStream protocol.UI_NotificationsServer) {
	log.Info("opening communication channel with new node...", notificationsStream)
	node := nodes.SetNotificationsChannel(notificationsStream)
	if node == nil {
		log.Warning("node not found, channel comms not opened")
		return
	}
	// XXX: go nodes.Channel(node) ?
	for {
		select {
		case <-node.NotificationsStream.Context().Done():
			log.Important("client.ChannelWithNode() Node exited: ", node.Addr())
			goto Exit
		case notif := <-node.GetNotifications():
			log.Important("client.ChannelWithNode() sending notification:", notif)
			node.NotificationsStream.Send(notif)
		}
	}

Exit:
	node.Close()
	return
}

// FIXME: remove when nodes implementation is done
func (c *Client) WaitForNodes() {
	<-c.nodesChan
}

// WaitForRules returns the channel where we listen for new outgoing connections.
func (c *Client) WaitForRules() chan *protocol.Connection {
	return c.rulesInChan
}

// AddNewRule sends a new rule to the node.
func (c *Client) AddNewRule(rule *protocol.Rule) {
	c.rulesOutChan <- rule
}
