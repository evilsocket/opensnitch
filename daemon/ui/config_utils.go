package ui

import (
	"fmt"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon/monitor"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/ui/config"
)

func (c *Client) getSocketPath(socketPath string) string {
	c.Lock()
	defer c.Unlock()

	if strings.HasPrefix(socketPath, "unix://") == true {
		c.isUnixSocket = true
		return socketPath[7:]
	}

	c.isUnixSocket = false
	return socketPath
}

func (c *Client) setSocketPath(socketPath string) {
	c.Lock()
	defer c.Unlock()

	c.socketPath = socketPath
}

func (c *Client) isProcMonitorEqual(newMonitorMethod string) bool {
	clientConfig.RLock()
	defer clientConfig.RUnlock()

	return newMonitorMethod == clientConfig.ProcMonitorMethod
}

func (c *Client) loadDiskConfiguration(reload bool) {
	raw, err := config.Load(configFile)
	if err != nil || len(raw) == 0 {
		// Sometimes we may receive 2 Write events on monitorConfigWorker,
		// Which may lead to read 0 bytes.
		log.Warning("Error loading configuration from disk %s: %s", configFile, err)
		return
	}

	if ok := c.loadConfiguration(raw); ok {
		if err := c.configWatcher.Add(configFile); err != nil {
			log.Error("Could not watch path: %s", err)
			return
		}
	}

	if reload {
		return
	}

	go c.monitorConfigWorker()
}

func (c *Client) loadConfiguration(rawConfig []byte) bool {
	var err error
	clientConfig, err = config.Parse(rawConfig)
	if err != nil {
		msg := fmt.Sprintf("Error parsing configuration %s: %s", configFile, err)
		log.Error(msg)
		c.SendWarningAlert(msg)
		return false
	}

	clientConfig.Lock()
	defer clientConfig.Unlock()

	// firstly load config level, to detect further errors if any
	if clientConfig.LogLevel != nil {
		log.SetLogLevel(int(*clientConfig.LogLevel))
	}
	log.SetLogUTC(clientConfig.LogUTC)
	log.SetLogMicro(clientConfig.LogMicro)
	if clientConfig.Server.LogFile != "" {
		log.Close()
		log.OpenFile(clientConfig.Server.LogFile)
	}

	if clientConfig.Server.Address != "" {
		tempSocketPath := c.getSocketPath(clientConfig.Server.Address)
		if tempSocketPath != c.socketPath {
			// disconnect, and let the connection poller reconnect to the new address
			c.disconnect()
		}
		c.setSocketPath(tempSocketPath)
	}
	if clientConfig.DefaultAction != "" {
		clientDisconnectedRule.Action = rule.Action(clientConfig.DefaultAction)
		clientErrorRule.Action = rule.Action(clientConfig.DefaultAction)
		// TODO: reconfigure connected rule if changed, but not save it to disk.
		//clientConnectedRule.Action = rule.Action(clientConfig.DefaultAction)
	}
	if clientConfig.DefaultDuration != "" {
		clientDisconnectedRule.Duration = rule.Duration(clientConfig.DefaultDuration)
		clientErrorRule.Duration = rule.Duration(clientConfig.DefaultDuration)
	}
	if clientConfig.ProcMonitorMethod != "" {
		if err := monitor.ReconfigureMonitorMethod(clientConfig.ProcMonitorMethod); err != nil {
			msg := fmt.Sprintf("Unable to set new process monitor (%s) method from disk: %v", clientConfig.ProcMonitorMethod, err)
			log.Warning(msg)
			c.SendWarningAlert(msg)
		}
	}

	// TODO:
	//c.stats.SetLimits(clientConfig.Stats)
	//loggers.Load(clientConfig.Server.Loggers, clientConfig.Stats.Workers)
	//stats.SetLoggers(loggers)

	return true
}
