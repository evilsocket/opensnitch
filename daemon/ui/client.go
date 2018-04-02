package ui

import (
	"net"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/rule"

	protocol "github.com/evilsocket/opensnitch/ui.proto"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

var clientDisconnectedRule = rule.Create("ui.client.disconnected", rule.Allow, rule.Once, rule.Cmp{
	What: rule.OpTrue,
})

var clientTimeoutRule = rule.Create("ui.client.timeout", rule.Allow, rule.Once, rule.Cmp{
	What: rule.OpTrue,
})

type Client struct {
	sync.Mutex

	socketPath string
	con        *grpc.ClientConn
	client     protocol.UIClient
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
		return err
	}

	c.client = protocol.NewUIClient(c.con)
	return nil
}

func (c *Client) Ask(con *conman.Connection) *rule.Rule {
	c.Lock()
	defer c.Unlock()

	if c.con == nil || c.con.GetState() != connectivity.Ready {
		if c.con != nil {
			log.Debug("Client state: %v", c.con.GetState())
		}
		return clientDisconnectedRule
	}

	log.Debug("Asking UI")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	_, err := c.client.AskRule(ctx, &protocol.RuleRequest{})
	if err != nil {
		log.Warning("Error while asking for rule: %s", err)
	} else {
		log.Debug("AskRule ok")
	}

	return clientDisconnectedRule
}
