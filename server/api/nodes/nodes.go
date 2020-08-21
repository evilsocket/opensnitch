package nodes

import (
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/ui/protocol"
	"golang.org/x/net/context"
	"google.golang.org/grpc/peer"
)

type nodeStats struct {
	events []*protocol.Event
	n      *node
}

var (
	nodeList  = make(map[string]*node)
	statsList = make(map[string]*nodeStats)
)

// Add a new node the list of nodes.
func Add(ctx context.Context, nodeConf *protocol.ClientConfig) {
	p := GetPeer(ctx)
	addr := p.Addr.String()
	nodeList[addr] = NewNode(ctx, nodeConf)
}

// SetNotificationsChannel sets the communication channel for a given node.
// https://github.com/grpc/grpc-go/blob/master/stream.go
func SetNotificationsChannel(notificationsStream protocol.UI_NotificationsServer) *node {
	ctx := notificationsStream.Context()
	addr := GetAddr(ctx)
	// ctx.AddCallback() ?
	if !isConnected(addr) {
		log.Warning("nodes.SetNotificationsChannel() not found: %s", addr)
		return nil
	}
	nodeList[addr].NotificationsStream = notificationsStream

	return nodeList[addr]
}

// UpdateStats of a node.
func UpdateStats(ctx context.Context, stats *protocol.Statistics) {
	addr := GetAddr(ctx)
	if !isConnected(addr) {
		log.Warning("nodes.UpdateStats() not found: %s", addr)
		return
	}
	nodeList[addr].UpdateStats(stats)
}

// Delete a node from the list of nodes.
func Delete(n *node) bool {
	n.Close()
	delete(nodeList, n.Addr())
	return true
}

// Get a node from the list of nodes.
func Get(addr string) *node {
	return nodeList[addr]
}

// GetPeer gets the address:port of a node.
func GetPeer(ctx context.Context) *peer.Peer {
	p, _ := peer.FromContext(ctx)
	return p
}

// GetAddr of a node from the context
func GetAddr(ctx context.Context) string {
	p := GetPeer(ctx)
	return p.Addr.String()
}

// GetAll nodes.
func GetAll() *map[string]*node {
	return &nodeList
}

// GetStats returns the stats of all nodes combined.
func GetStats() (stats []*protocol.Statistics) {
	for addr, node := range *GetAll() {
		println(addr, node)
	}

	return stats
}

// Total returns the number of saved nodes.
func Total() int {
	return len(nodeList)
}

func isConnected(addr string) bool {
	_, found := nodeList[addr]
	return found
}
