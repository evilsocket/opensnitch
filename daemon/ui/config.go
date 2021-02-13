package ui

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/rule"
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
	config.RLock()
	defer config.RUnlock()

	return newMonitorMethod == config.ProcMonitorMethod
}

func (c *Client) parseConf(rawConfig string) (conf Config, err error) {
	err = json.Unmarshal([]byte(rawConfig), &conf)
	return conf, err
}

func (c *Client) loadDiskConfiguration(reload bool) {
	raw, err := ioutil.ReadFile(configFile)
	if err != nil {
		fmt.Errorf("Error loading disk configuration %s: %s", configFile, err)
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
	config.Lock()
	defer config.Unlock()

	if err := json.Unmarshal(rawConfig, &config); err != nil {
		log.Error("Error parsing configuration %s: %s", configFile, err)
		return false
	}
	// firstly load config level, to detect further errors if any
	if config.LogLevel != nil {
		log.SetLogLevel(int(*config.LogLevel))
	}
	if config.Server.LogFile != "" {
		log.Close()
		log.OpenFile(config.Server.LogFile)
	}

	if config.Server.Address != "" {
		tempSocketPath := c.getSocketPath(config.Server.Address)
		if tempSocketPath != c.socketPath {
			// disconnect, and let the connection poller reconnect to the new address
			c.disconnect()
		}
		c.setSocketPath(tempSocketPath)
	}
	if config.DefaultAction != "" {
		clientDisconnectedRule.Action = rule.Action(config.DefaultAction)
		clientErrorRule.Action = rule.Action(config.DefaultAction)
	}
	if config.DefaultDuration != "" {
		clientDisconnectedRule.Duration = rule.Duration(config.DefaultDuration)
		clientErrorRule.Duration = rule.Duration(config.DefaultDuration)
	}
	if config.ProcMonitorMethod != "" {
		procmon.SetMonitorMethod(config.ProcMonitorMethod)
	}

	return true
}

func (c *Client) saveConfiguration(rawConfig string) (err error) {
	if c.loadConfiguration([]byte(rawConfig)) != true {
		return fmt.Errorf("Error parsing configuration %s: %s", rawConfig, err)
	}

	if err = ioutil.WriteFile(configFile, []byte(rawConfig), 0644); err != nil {
		log.Error("writing configuration to disk: %s", err)
		return err
	}
	return nil
}
