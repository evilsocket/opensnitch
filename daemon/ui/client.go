package ui

import (
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

	"github.com/fsnotify/fsnotify"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

var (
	configFile             = "/etc/opensnitchd/default-config.json"
	dummyOperator, _       = rule.NewOperator(rule.Simple, rule.OpTrue, "", make([]rule.Operator, 0))
	clientDisconnectedRule = rule.Create("ui.client.disconnected", true, rule.Allow, rule.Once, dummyOperator)
	clientErrorRule        = rule.Create("ui.client.error", true, rule.Allow, rule.Once, dummyOperator)
	config                 Config
)

// Config holds the values loaded from configFile
type Config struct {
	sync.RWMutex
	DefaultAction     string
	DefaultDuration   string
	InterceptUnknown  bool
	ProcMonitorMethod string
	LogLevel          *uint32
}

// Client holds the connection information of a client.
type Client struct {
	sync.Mutex
	clientCtx    context.Context
	clientCancel context.CancelFunc

	stats               *statistics.Statistics
	rules               *rule.Loader
	socketPath          string
	isUnixSocket        bool
	con                 *grpc.ClientConn
	client              protocol.UIClient
	configWatcher       *fsnotify.Watcher
	streamNotifications protocol.UI_NotificationsClient
}

// NewClient creates and configures a new client.
func NewClient(path string, stats *statistics.Statistics, rules *rule.Loader) *Client {

	c := &Client{
		socketPath:   path,
		stats:        stats,
		rules:        rules,
		isUnixSocket: false,
	}
	c.clientCtx, c.clientCancel = context.WithCancel(context.Background())

	if watcher, err := fsnotify.NewWatcher(); err == nil {
		c.configWatcher = watcher
	}
	if strings.HasPrefix(c.socketPath, "unix://") == true {
		c.isUnixSocket = true
		c.socketPath = c.socketPath[7:]
	}
	c.loadDiskConfiguration(false)

	go c.poller()
	return c
}

// Close cancels the running tasks: pinging the server and (re)connection poller.
func (c *Client) Close() {
	c.clientCancel()
}

// ProcMonitorMethod returns the monitor method configured.
// If it's not present in the config file, it'll return an emptry string.
func (c *Client) ProcMonitorMethod() string {
	config.RLock()
	defer config.RUnlock()
	return config.ProcMonitorMethod
}

// InterceptUnknown returns
func (c *Client) InterceptUnknown() bool {
	config.RLock()
	defer config.RUnlock()
	return config.InterceptUnknown
}

// DefaultAction returns the default configured action for
func (c *Client) DefaultAction() rule.Action {
	return clientDisconnectedRule.Action
}

// DefaultDuration returns the default duration configured for a rule.
// For example it can be: once, always, "until restart".
func (c *Client) DefaultDuration() rule.Duration {
	return clientDisconnectedRule.Duration
}

// Connected checks if the client has established a connection with the server.
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
	for {
		select {
		case <-c.clientCtx.Done():
			goto Exit
		default:
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
			}
			if c.Connected() == true {
				// if the client is connected and ready, send a ping
				if err := c.ping(time.Now()); err != nil {
					log.Warning("Error while pinging UI service: %s", err)
				}
			}

			time.Sleep(1 * time.Second)
		}
	}
Exit:
	log.Info("uiClient exit")
}

func (c *Client) onStatusChange(connected bool) {
	if connected {
		log.Info("Connected to the UI service on %s", c.socketPath)
		go c.Subscribe()
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
		return fmt.Errorf("service is not connected")
	}

	c.Lock()
	defer c.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reqID := uint64(ts.UnixNano())

	pReq := &protocol.PingRequest{
		Id:    reqID,
		Stats: c.stats.Serialize(),
	}
	c.stats.RLock()
	pong, err := c.client.Ping(ctx, pReq)
	c.stats.RUnlock()
	if err != nil {
		return err
	}

	if pong.Id != reqID {
		return fmt.Errorf("Expected pong with id 0x%x, got 0x%x", reqID, pong.Id)
	}

	return nil
}

// Ask sends a request to the server, with the values of a connection to be
// allowed or denied.
func (c *Client) Ask(con *conman.Connection) (*rule.Rule, bool) {
	if c.Connected() == false {
		return clientDisconnectedRule, false
	}

	c.Lock()
	defer c.Unlock()

	// FIXME: if timeout is fired, the rule is not added to the list in the GUI
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
	defer cancel()
	reply, err := c.client.AskRule(ctx, con.Serialize())
	if err != nil {
		log.Warning("Error while asking for rule: %s - %v", err, con)
		return nil, false
	}

	r, err := rule.Deserialize(reply)
	if err != nil {
		return nil, false
	}
	return r, true
}

func (c *Client) monitorConfigWorker() {
	for {
		select {
		case event := <-c.configWatcher.Events:
			if (event.Op&fsnotify.Write == fsnotify.Write) || (event.Op&fsnotify.Remove == fsnotify.Remove) {
				c.loadDiskConfiguration(true)
			}
		}
	}
}
