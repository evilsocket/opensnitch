package nodes

import (
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/ui/protocol"
	"golang.org/x/net/context"
	"google.golang.org/grpc/peer"
)

var (
	nodeList = make(map[string]*node)
)

// Add a new node the list of nodes.
func Add(ctx context.Context, nodeConf *protocol.ClientConfig) {
	p, _ := peer.FromContext(ctx)
	s := p.Addr.String()
	nodeList[s] = NewNode(ctx, nodeConf)
}

// Update sets the communication channel for a given node.
// https://github.com/grpc/grpc-go/blob/master/stream.go
func Update(notificationsStream protocol.UI_NotificationsServer) *node {
	ctx := notificationsStream.Context()
	p, _ := peer.FromContext(ctx)
	addr := p.Addr.String()
	// ctx.AddCallback() ?
	_, found := nodeList[addr]
	if !found {
		log.Warning("nodes.Update() not found: %s", addr)
		return nil
	}
	nodeList[p.Addr.String()].NotificationsStream = notificationsStream

	return nodeList[addr]
}

// Delete a node from the list of nodes.
func Delete(addr string) bool {
	delete(nodeList, addr)
	return true
}

// Get a node from the list of nodes.
func Get(addr string) *node {
	return nodeList[addr]
}

// GetAll nodes.
func GetAll() *map[string]*node {
	return &nodeList
}

// Total returns the number of saved nodes.
func Total() int {
	return len(nodeList)
}
