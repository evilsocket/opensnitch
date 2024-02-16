package ui

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/firewall/iptables"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/loggers"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/statistics"
	"github.com/evilsocket/opensnitch/daemon/ui/auth"
	"github.com/evilsocket/opensnitch/daemon/ui/config"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/keepalive"
)

var (
	configFile             = "/etc/opensnitchd/default-config.json"
	dummyOperator, _       = rule.NewOperator(rule.Simple, false, rule.OpTrue, "", make([]rule.Operator, 0))
	clientDisconnectedRule = rule.Create("ui.client.disconnected", "", true, false, false, rule.Allow, rule.Once, dummyOperator)
	// While the GUI is connected, deny by default everything until the user takes an action.
	clientConnectedRule = rule.Create("ui.client.connected", "", true, false, false, rule.Deny, rule.Once, dummyOperator)
	clientErrorRule     = rule.Create("ui.client.error", "", true, false, false, rule.Allow, rule.Once, dummyOperator)
	clientConfig        config.Config

	maxQueuedAlerts = 1024
)

// Client holds the connection information of a client.
type Client struct {
	client              protocol.UIClient
	streamNotifications protocol.UI_NotificationsClient
	clientCtx           context.Context
	clientCancel        context.CancelFunc

	stats         *statistics.Statistics
	rules         *rule.Loader
	con           *grpc.ClientConn
	configWatcher *fsnotify.Watcher

	alertsChan  chan protocol.Alert
	isConnected chan bool

	socketPath     string
	unixSockPrefix string

	//isAsking is set to true if the client is awaiting a decision from the GUI
	isAsking     bool
	isUnixSocket bool

	sync.RWMutex
}

// NewClient creates and configures a new client.
func NewClient(socketPath, localConfigFile string, stats *statistics.Statistics, rules *rule.Loader, loggers *loggers.LoggerManager) *Client {
	if localConfigFile != "" {
		configFile = localConfigFile
	}
	c := &Client{
		stats:        stats,
		rules:        rules,
		isUnixSocket: false,
		isAsking:     false,
		isConnected:  make(chan bool),
		alertsChan:   make(chan protocol.Alert, maxQueuedAlerts),
	}
	//for i := 0; i < 4; i++ {
	go c.alertsDispatcher()

	c.clientCtx, c.clientCancel = context.WithCancel(context.Background())

	if watcher, err := fsnotify.NewWatcher(); err == nil {
		c.configWatcher = watcher
	}
	c.loadDiskConfiguration(false)
	if socketPath != "" {
		c.setSocketPath(c.getSocketPath(socketPath))
	}
	procmon.EventsCache.SetComputeChecksums(clientConfig.Rules.EnableChecksums)
	rules.EnableChecksums(clientConfig.Rules.EnableChecksums)
	loggers.Load(clientConfig.Server.Loggers, clientConfig.Stats.Workers)
	stats.SetLimits(clientConfig.Stats)
	stats.SetLoggers(loggers)

	return c
}

// Connect starts the connection poller
func (c *Client) Connect() {
	go c.poller()
}

// Close cancels the running tasks: pinging the server and (re)connection poller.
func (c *Client) Close() {
	c.clientCancel()
}

// ProcMonitorMethod returns the monitor method configured.
// If it's not present in the config file, it'll return an empty string.
func (c *Client) ProcMonitorMethod() string {
	clientConfig.RLock()
	defer clientConfig.RUnlock()
	return clientConfig.ProcMonitorMethod
}

// InterceptUnknown returns
func (c *Client) InterceptUnknown() bool {
	clientConfig.RLock()
	defer clientConfig.RUnlock()
	return clientConfig.InterceptUnknown
}

// GetFirewallType returns the firewall to use
func (c *Client) GetFirewallType() string {
	clientConfig.RLock()
	defer clientConfig.RUnlock()
	if clientConfig.Firewall == "" {
		return iptables.Name
	}
	return clientConfig.Firewall
}

// DefaultAction returns the default configured action for
func (c *Client) DefaultAction() rule.Action {
	isConnected := c.Connected()

	c.RLock()
	defer c.RUnlock()

	if isConnected {
		return clientConnectedRule.Action
	}

	return clientDisconnectedRule.Action
}

// DefaultDuration returns the default duration configured for a rule.
// For example it can be: once, always, "until restart".
func (c *Client) DefaultDuration() rule.Duration {
	c.RLock()
	defer c.RUnlock()
	return clientDisconnectedRule.Duration
}

// Connected checks if the client has established a connection with the server.
func (c *Client) Connected() bool {
	c.RLock()
	defer c.RUnlock()
	if c.con == nil || c.con.GetState() != connectivity.Ready {
		return false
	}
	return true
}

//GetIsAsking returns the isAsking flag
func (c *Client) GetIsAsking() bool {
	c.RLock()
	defer c.RUnlock()
	return c.isAsking
}

//SetIsAsking sets the isAsking flag
func (c *Client) SetIsAsking(flag bool) {
	c.Lock()
	defer c.Unlock()
	c.isAsking = flag
}

func (c *Client) poller() {
	log.Debug("UI service poller started for socket %s", c.socketPath)
	wasConnected := false
	for {
		select {
		case <-c.clientCtx.Done():
			log.Info("Client.poller() exit, Done()")
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
					log.Warning("Error while pinging UI service: %s, state: %v", err, c.con.GetState())
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

		select {
		case c.isConnected <- true:
		default:
		}
	} else {
		log.Error("Connection to the UI service lost.")
		c.disconnect()
	}
}

func (c *Client) connect() (err error) {
	if c.Connected() {
		return
	}

	if c.con != nil {
		if c.con.GetState() == connectivity.TransientFailure || c.con.GetState() == connectivity.Shutdown {
			c.disconnect()
		} else {
			return
		}
	}

	if err := c.openSocket(); err != nil {
		log.Debug("connect() %s", err)
		c.disconnect()
		return err
	}

	if c.client == nil {
		c.client = protocol.NewUIClient(c.con)
	}
	return nil
}

func (c *Client) openSocket() (err error) {
	c.Lock()
	defer c.Unlock()

	dialOption, err := auth.New(&clientConfig)
	if err != nil {
		return fmt.Errorf("Invalid client auth options: %s", err)
	}
	if c.isUnixSocket {
		c.con, err = grpc.Dial(c.socketPath, dialOption,
			grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout(c.unixSockPrefix, addr, timeout)
			}))
	} else {
		// https://pkg.go.dev/google.golang.org/grpc/keepalive#ClientParameters
		var kacp = keepalive.ClientParameters{
			Time: 5 * time.Second,
			// if there's no activity after ^, wait 20s and close
			// server timeout is 20s by default.
			Timeout: 22 * time.Second,
			// send pings even without active streams
			PermitWithoutStream: true,
		}

		c.con, err = grpc.Dial(c.socketPath, dialOption, grpc.WithKeepaliveParams(kacp))
	}

	return err
}

func (c *Client) disconnect() {
	c.Lock()
	defer c.Unlock()

	select {
	case c.isConnected <- false:
	default:
	}
	if c.con != nil {
		c.con.Close()
		c.con = nil
		log.Debug("client.disconnect()")
	}
	c.client = nil
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
func (c *Client) Ask(con *conman.Connection) *rule.Rule {
	if c.client == nil {
		return nil
	}

	// FIXME: if timeout is fired, the rule is not added to the list in the GUI
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
	defer cancel()
	reply, err := c.client.AskRule(ctx, con.Serialize())
	if err != nil {
		log.Warning("Error while asking for rule: %s - %v", err, con)
		return nil
	}

	r, err := rule.Deserialize(reply)
	if err != nil {
		return nil
	}
	return r
}

// PostAlert queues a new message to be delivered to the server
func (c *Client) PostAlert(atype protocol.Alert_Type, awhat protocol.Alert_What, action protocol.Alert_Action, prio protocol.Alert_Priority, data interface{}) {
	if len(c.alertsChan) > maxQueuedAlerts-1 {
		// pop oldest alert if channel is full
		log.Debug("PostAlert() queue full, popping alert (%d)", len(c.alertsChan))
		<-c.alertsChan
	}
	if c.Connected() == false {
		log.Debug("UI not connected, queueing alert: %d", len(c.alertsChan))
	}
	c.alertsChan <- *NewAlert(atype, awhat, action, prio, data)
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
