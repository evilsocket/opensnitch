package ui

import (
	"encoding/json"
	"io/ioutil"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/conman"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/rule"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/statistics"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/ui/protocol"

	"golang.org/x/net/context"

	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

var (
	configFile			 = "/etc/opensnitchd/default-config.json"
	clientDisconnectedRule = rule.Create("ui.client.disconnected", rule.Allow, rule.Once, rule.NewOperator(rule.Simple, rule.OpTrue, "", make([]rule.Operator, 0)))
	clientErrorRule		= rule.Create("ui.client.error", rule.Allow, rule.Once, rule.NewOperator(rule.Simple, rule.OpTrue, "", make([]rule.Operator, 0)))
	config  Config
)

type Config struct {
	sync.RWMutex
	Default_Action   string
	Default_Duration string
	Intercept_Unknown bool
}

type Client struct {
	sync.Mutex

	stats		*statistics.Statistics
	socketPath   string
	isUnixSocket bool
	con		  *grpc.ClientConn
	client	   protocol.UIClient
	configWatcher *fsnotify.Watcher
}

func NewClient(path string, stats *statistics.Statistics) *Client {
	c := &Client{
		socketPath:   path,
		stats:		stats,
		isUnixSocket: false,
	}
	if watcher, err := fsnotify.NewWatcher(); err == nil {
		c.configWatcher = watcher
	}
	if strings.HasPrefix(c.socketPath, "unix://") == true {
		c.isUnixSocket = true
		c.socketPath = c.socketPath[7:]
	}
	c.loadConfiguration(false)

	go c.poller()
	return c
}

func (c *Client) loadConfiguration(reload bool) {
	raw, err := ioutil.ReadFile(configFile)
	if err != nil {
		fmt.Errorf("Error loading configuration %s: %s", configFile, err)
	}

	config.Lock()
	defer config.Unlock()

	err = json.Unmarshal(raw, &config)
	if err != nil {
		fmt.Errorf("Error parsing configuration %s: %s", configFile, err)
	}

	if config.Default_Action != "" {
		clientDisconnectedRule.Action = rule.Action(config.Default_Action)
		clientErrorRule.Action = rule.Action(config.Default_Action)
	}
	if config.Default_Duration != "" {
		clientDisconnectedRule.Duration = rule.Duration(config.Default_Duration)
		clientErrorRule.Duration = rule.Duration(config.Default_Duration)
	}

	if err := c.configWatcher.Add(configFile); err != nil {
		log.Error("Could not watch path: %s", err)
		return
	}
	if reload == true {
		return
	}

	go c.monitorConfigWorker()
}

func (c *Client) InterceptUnknown() bool {
	config.RLock()
	defer config.RUnlock()
	return config.Intercept_Unknown
}

func (c *Client) DefaultAction() rule.Action {
	return clientDisconnectedRule.Action
}

func (c *Client) DefaultDuration() rule.Duration {
	return clientDisconnectedRule.Duration
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

		if c.Connected() == false {
			// connect and create the client if needed
			if err := c.connect(); err != nil {
				log.Warning("Error while connecting to UI service: %s", err)
			}
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
		c.client = nil
		c.con.Close()
	}
}

func (c *Client) connect() (err error) {
	if c.Connected() {
		return
	}
	c.Lock()
	defer c.Unlock()

	if c.con != nil {
		if c.con.GetState() == connectivity.TransientFailure || c.con.GetState() == connectivity.Shutdown {
			c.client = nil
			c.con.Close()
		} else {
			return
		}
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
		if c.con != nil {
			c.con.Close()
		}
		c.con = nil
		c.client = nil
		return err
	}

	if c.client == nil {
		c.client = protocol.NewUIClient(c.con)
	}
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

	pReq := &protocol.PingRequest{
		Id:	reqId,
		Stats: c.stats.Serialize(),
	}
	c.stats.RLock()
	pong, err := c.client.Ping(ctx, pReq)
	c.stats.RUnlock()
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

func(c *Client) monitorConfigWorker () {
	for {
		select {
		case event := <-c.configWatcher.Events:
			if (event.Op&fsnotify.Write == fsnotify.Write) || (event.Op&fsnotify.Remove == fsnotify.Remove) {
				c.loadConfiguration(true)
			}
		}
	}
}
