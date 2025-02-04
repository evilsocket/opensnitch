package netlink

import (
	vnl "github.com/vishvananda/netlink"
)

// SocketGetXDP dumps all the opened XDP sockets from kernel
func SocketGetXDP() ([]*vnl.XDPDiagInfoResp, error) {
	// TODO: enable filtering
	return vnl.SocketDiagXDP()
}
