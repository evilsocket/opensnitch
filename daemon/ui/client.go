package ui

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/statistics"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

var (
	clientDisconnectedRule = rule.Create("ui.client.disconnected", rule.Allow, rule.Once, rule.NewOperator(rule.Simple, rule.OpTrue, "", make([]rule.Operator, 0)))
	clientErrorRule        = rule.Create("ui.client.error", rule.Allow, rule.Once, rule.NewOperator(rule.Simple, rule.OpTrue, "", make([]rule.Operator, 0)))
)

type Client struct {
	sync.Mutex

	stats        *statistics.Statistics
	socketPath   string
	isUnixSocket bool
	con          *grpc.ClientConn
	client       protocol.UIClient
}

func NewClient(path string, stats *statistics.Statistics) *Client {
	c := &Client{
		socketPath:   path,
		stats:        stats,
		isUnixSocket: false,
	}
	if strings.HasPrefix(c.socketPath, "unix://") == true {
		c.isUnixSocket = true
		c.socketPath = c.socketPath[7:]
	}

	go c.poller()
	return c
}

func (c *Client) Connected() bool {
	c.Lock()
	defer c.Unlock()
	if c.con == nil || c.con.GetState() != connectivity.Ready {
		return false
	}
	return true
}

func (c *Client) poller() {
	log.Debug("UI service poller started for socket %s", c.socketPath)
	wasConnected := false
	for true {
		isConnected := c.Connected()
		if wasConnected != isConnected {
			c.onStatusChange(isConnected)
			wasConnected = isConnected
		}

		// connect and create the client if needed
		if err := c.connect(); err != nil {
			log.Warning("Error while connecting to UI service: %s", err)
		} else if c.Connected() == true {
			// if the client is connected and ready, send a ping
			if err := c.ping(time.Now()); err != nil {
				log.Warning("Error while pinging UI service: %s", err)
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func (c *Client) onStatusChange(connected bool) {
	if connected {
		log.Info("Connected to the UI service on %s", c.socketPath)
	} else {
		log.Error("Connection to the UI service lost.")
	}
}

func (c *Client) connect() (err error) {
	if c.Connected() {
		return
	}

	if c.isUnixSocket {
		c.con, err = grpc.Dial(c.socketPath, grpc.WithInsecure(),
			grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("unix", addr, timeout)
			}))
	} else {
		c.con, err = grpc.Dial(c.socketPath, grpc.WithInsecure())
	}

	if err != nil {
		c.con = nil
		return err
	}

	c.client = protocol.NewUIClient(c.con)
	return nil
}

func (c *Client) ping(ts time.Time) (err error) {
	if c.Connected() == false {
		return fmt.Errorf("service is not connected.")
	}

	c.Lock()
	defer c.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reqId := uint64(ts.UnixNano())

	pong, err := c.client.Ping(ctx, &protocol.PingRequest{
		Id:    reqId,
		Stats: c.stats.Serialize(),
	})
	if err != nil {
		return err
	}

	if pong.Id != reqId {
		return fmt.Errorf("Expected pong with id 0x%x, got 0x%x", reqId, pong.Id)
	}

	return nil
}

func (c *Client) Ask(con *conman.Connection) (*rule.Rule, bool) {
	if c.Connected() == false {
		return clientDisconnectedRule, false
	}

	c.Lock()
	defer c.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	reply, err := c.client.AskRule(ctx, con.Serialize())
	if err != nil {
		log.Warning("Error while asking for rule: %s", err)
		return clientErrorRule, false
	}

	return rule.Deserialize(reply), true
}
