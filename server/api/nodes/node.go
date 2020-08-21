package nodes

import (
	"fmt"
	"net"
	"time"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/ui/protocol"
	"golang.org/x/net/context"
	"google.golang.org/grpc/peer"
)

// Status represents the current connectivity status of a node.
type Status string

// Statuses of a node.
var (
	Online  = Status(log.Bold(log.Green("online")))
	Offline = Status(log.Bold(log.Red("offline")))
)

type node struct {
	addr                 net.Addr
	ctx                  context.Context
	lastSeen             time.Time
	status               Status
	NotificationsStream  protocol.UI_NotificationsServer
	notificationsChannel chan *protocol.Notification
	config               *protocol.ClientConfig
	stats                *protocol.Statistics
}

// NewNode instanstiates a new node.
func NewNode(ctx context.Context, nodeConf *protocol.ClientConfig) *node {
	p, _ := peer.FromContext(ctx)
	log.Info("NewNode: %s - %s, %v", nodeConf.Name, nodeConf.Version, p.Addr)
	return &node{
		addr:                 p.Addr,
		ctx:                  ctx,
		lastSeen:             time.Now(),
		status:               Online,
		config:               nodeConf,
		notificationsChannel: make(chan *protocol.Notification, 1),
	}
}

func (n *node) String() string {
	return fmt.Sprintf("[%v] [%10s] %s - %s", n.lastSeen, n.addr, n.config.Name, n.config.Version)
}

// Addr returns the address of the node.
func (n *node) Addr() string {
	return n.addr.String()
}

func (n *node) Close() {
	n.status = Offline
}

func (n *node) Status() Status {
	return n.status
}

// LastSeen returns the last time the node was seen by the server.
func (n *node) LastSeen() time.Time {
	return n.lastSeen
}

// SendNotification to the node via the channel and grpc.ServerStream channel.
func (n *node) SendNotification(notif *protocol.Notification) {
	n.notificationsChannel <- notif
}

func (n *node) UpdateStats(stats *protocol.Statistics) {
	n.stats = stats
	n.lastSeen = time.Now()
}

func (n *node) GetConfig() *protocol.ClientConfig {
	return n.config
}

// GetNotifications returns the notifications channel.
func (n *node) GetNotifications() chan *protocol.Notification {
	return n.notificationsChannel
}
