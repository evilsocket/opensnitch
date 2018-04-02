package ui

import (
	"net"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/rule"

	"google.golang.org/grpc"
)

var clientDisconnectedRule = rule.Create("ui.client.disconnected", rule.Allow, rule.Once, rule.Cmp{
	What: rule.OpTrue,
})

type Client struct {
	sync.Mutex

	socketPath string
	con        *grpc.ClientConn
}

func NewClient(path string) *Client {
	c := &Client{
		socketPath: path,
	}
	go c.poller()
	return c
}

func (c *Client) poller() {
	log.Debug("UI service poller started for socket %s", c.socketPath)
	t := time.NewTicker(time.Second * 1)
	for _ = range t.C {
		err := c.connect()
		if err != nil {
			log.Warning("Error while connecting to UI service: %s", err)
		}
	}
}

func (c *Client) connect() (err error) {
	c.Lock()
	defer c.Unlock()

	if c.con != nil {
		return
	}

	c.con, err = grpc.Dial(c.socketPath, grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}))
	if err != nil {
		c.con = nil
	}
	return err

}

func (c *Client) Ask(con *conman.Connection) *rule.Rule {
	c.Lock()
	defer c.Unlock()

	// TODO: if connected, send request

	return clientDisconnectedRule
}
