package ui

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/statistics"

	protocol "github.com/evilsocket/opensnitch/proto"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

var clientDisconnectedRule = rule.Create("ui.client.disconnected", rule.Allow, rule.Once, rule.Cmp{
	What: rule.OpTrue,
})

var clientErrorRule = rule.Create("ui.client.error", rule.Allow, rule.Once, rule.Cmp{
	What: rule.OpTrue,
})

type Client struct {
	sync.Mutex

	stats      *statistics.Statistics
	socketPath string
	con        *grpc.ClientConn
	client     protocol.UIClient
}

func NewClient(path string, stats *statistics.Statistics) *Client {
	c := &Client{
		socketPath: path,
		stats:      stats,
	}
	go c.poller()
	return c
}

func (c *Client) poller() {
	log.Debug("UI service poller started for socket %s", c.socketPath)
	t := time.NewTicker(time.Second * 1)
	for ts := range t.C {
		if err := c.connect(); err != nil {
			log.Warning("Error while connecting to UI service: %s", err)
		} else if c.con.GetState() == connectivity.Ready {
			if err := c.ping(ts); err != nil {
				log.Warning("Error while pinging UI service: %s", err)
			} else {
				log.Debug("Got pong")
			}
		} else {
			log.Debug("Skipped ping/pong, connection not ready.")
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

func (c *Client) ping(ts time.Time) (err error) {
	c.Lock()
	defer c.Unlock()

	if c.con == nil || c.client == nil {
		return fmt.Errorf("service is not connected.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reqId := uint64(ts.UnixNano())

	c.stats.Lock()
	defer c.stats.Unlock()

	pong, err := c.client.Ping(ctx, &protocol.PingRequest{
		Id: reqId,
		Stats: &protocol.Statistics{
			Uptime:       uint64(time.Since(c.stats.Started).Seconds()),
			DnsResponses: uint64(c.stats.DNSResponses),
			Connections:  uint64(c.stats.Connections),
			Ignored:      uint64(c.stats.Ignored),
			Accepted:     uint64(c.stats.Accepted),
			Dropped:      uint64(c.stats.Dropped),
			RuleHits:     uint64(c.stats.RuleHits),
			RuleMisses:   uint64(c.stats.RuleMisses),
			ByProto:      c.stats.ByProto,
			ByAddress:    c.stats.ByAddress,
			ByHost:       c.stats.ByHost,
			ByPort:       c.stats.ByPort,
			ByUid:        c.stats.ByUID,
			ByExecutable: c.stats.ByExecutable,
		},
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
	c.Lock()
	defer c.Unlock()

	if c.con == nil || c.con.GetState() != connectivity.Ready {
		if c.con != nil {
			log.Debug("Client state: %v", c.con.GetState())
		}
		return clientDisconnectedRule, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	reply, err := c.client.AskRule(ctx, con.ToRequest())
	if err != nil {
		log.Warning("Error while asking for rule: %s", err)
		return clientErrorRule, false
	}

	return rule.FromReply(reply), true
}
