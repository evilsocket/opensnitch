package ui

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
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

func (c *Client) parseConf(rawConfig string) (conf config.Config, err error) {
	err = json.Unmarshal([]byte(rawConfig), &conf)
	return conf, err
}

func (c *Client) loadDiskConfiguration(reload bool) {
	raw, err := ioutil.ReadFile(configFile)
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
	clientConfig.Lock()
	defer clientConfig.Unlock()

	if err := json.Unmarshal(rawConfig, &clientConfig); err != nil {
		msg := fmt.Sprintf("Error parsing configuration %s: %s", configFile, err)
		log.Error(msg)
		c.SendWarningAlert(msg)
		return false
	}
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

	return true
}

func (c *Client) saveConfiguration(rawConfig string) (err error) {
	if _, err = c.parseConf(rawConfig); err != nil {
		return fmt.Errorf("Error parsing configuration %s: %s", rawConfig, err)
	}

	if err = os.Chmod(configFile, 0600); err != nil {
		log.Warning("unable to set permissions to default config: %s", err)
	}
	if err = ioutil.WriteFile(configFile, []byte(rawConfig), 0644); err != nil {
		log.Error("writing configuration to disk: %s", err)
		return err
	}
	return nil
}
