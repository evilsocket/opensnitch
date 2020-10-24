package ui

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/procmon"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/rule"
)

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
		fmt.Errorf("Error parsing configuration %s: %s", configFile, err)
		return false
	}

	if config.DefaultAction != "" {
		clientDisconnectedRule.Action = rule.Action(config.DefaultAction)
		clientErrorRule.Action = rule.Action(config.DefaultAction)
	}
	if config.DefaultDuration != "" {
		clientDisconnectedRule.Duration = rule.Duration(config.DefaultDuration)
		clientErrorRule.Duration = rule.Duration(config.DefaultDuration)
	}
	if config.LogLevel != nil {
		log.SetLogLevel(int(*config.LogLevel))
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
		log.Error("writing configuration to disk: ", err)
		return err
	}
	return nil
}
