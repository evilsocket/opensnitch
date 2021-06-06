// Package config provides functionality to load and monitor the system
// firewall rules.
// It's inherited by the different firewall packages (iptables, nftables).
//
// The firewall rules defined by the user are reloaded in these cases:
// - When the file system-fw.json changes.
// - When the firewall rules are not present when listing them.
//
package config

import (
	"encoding/json"
	"io/ioutil"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/fsnotify/fsnotify"
)

type callback func()

// FwRule holds the fields of a rule
type FwRule struct {
	sync.RWMutex

	Description      string
	Table            string
	Chain            string
	Parameters       string
	Target           string
	TargetParameters string
}

type rulesList struct {
	sync.RWMutex

	Rule *FwRule
}

// SystemConfig holds the list of rules to be added to the system
type SystemConfig struct {
	sync.RWMutex
	SystemRules []*rulesList
}

// Config holds the functionality to re/load the firewall configuration from disk.
// This is the configuration to manage the system firewall (iptables, nftables).
type Config struct {
	sync.Mutex

	file            string
	watcher         *fsnotify.Watcher
	monitorExitChan chan bool
	SysConfig       SystemConfig

	// subscribe to this channel to receive config reload events
	ReloadConfChan chan bool

	// preloadCallback is called before reloading the configuration,
	// in order to delete old fw rules.
	preloadCallback callback
}

// NewSystemFwConfig initializes config fields
func (c *Config) NewSystemFwConfig(preLoadCb callback) (*Config, error) {
	var err error
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warning("Error creating firewall config watcher: %s", err)
		return nil, err
	}

	c.Lock()
	defer c.Unlock()

	c.file = "/etc/opensnitchd/system-fw.json"
	c.monitorExitChan = make(chan bool, 1)
	c.preloadCallback = preLoadCb
	c.watcher = watcher
	c.ReloadConfChan = make(chan bool, 1)
	return c, nil
}

// LoadDiskConfiguration reads and loads the firewall configuration from disk
func (c *Config) LoadDiskConfiguration(reload bool) {
	c.Lock()
	defer c.Unlock()

	raw, err := ioutil.ReadFile(c.file)
	if err != nil {
		log.Error("Error reading firewall configuration from disk %s: %s", c.file, err)
		return
	}

	c.loadConfiguration(raw)
	// we need to monitor the configuration file for changes, regardless if it's
	// malformed or not.
	c.watcher.Remove(c.file)
	if err := c.watcher.Add(c.file); err != nil {
		log.Error("Could not watch firewall configuration: %s", err)
		return
	}

	if reload {
		c.ReloadConfChan <- true
		return
	}

	go c.monitorConfigWorker()
}

// loadConfigutation reads the system firewall rules from disk.
// Then the rules are added based on the configuration defined.
func (c *Config) loadConfiguration(rawConfig []byte) {
	c.SysConfig.Lock()
	defer c.SysConfig.Unlock()

	// delete old system rules, that may be different from the new ones
	c.preloadCallback()

	if err := json.Unmarshal(rawConfig, &c.SysConfig); err != nil {
		// we only log the parser error, giving the user a chance to write a valid config
		log.Error("Error parsing firewall configuration %s: %s", c.file, err)
	}
	log.Info("fw configuration loaded")
}

func (c *Config) saveConfiguration(rawConfig string) error {
	conf, err := json.Marshal([]byte(rawConfig))
	if err != nil {
		log.Error("saving json firewall configuration: %s %s", err, conf)
		return err
	}

	c.loadConfiguration([]byte(rawConfig))

	if err = ioutil.WriteFile(c.file, []byte(rawConfig), 0644); err != nil {
		log.Error("writing firewall configuration to disk: %s", err)
		return err
	}
	return nil
}

// StopConfigWatcher stops the configuration watcher and stops the subroutine.
func (c *Config) StopConfigWatcher() {
	c.Lock()
	defer c.Unlock()

	if c.monitorExitChan != nil {
		c.monitorExitChan <- true
		close(c.monitorExitChan)
	}
	if c.ReloadConfChan != nil {
		c.ReloadConfChan <- false // exit
		close(c.ReloadConfChan)
	}

	if c.watcher != nil {
		c.watcher.Remove(c.file)
		c.watcher.Close()
	}
}

func (c *Config) monitorConfigWorker() {
	for {
		select {
		case <-c.monitorExitChan:
			goto Exit
		case event := <-c.watcher.Events:
			if (event.Op&fsnotify.Write == fsnotify.Write) || (event.Op&fsnotify.Remove == fsnotify.Remove) {
				c.LoadDiskConfiguration(true)
			}
		}
	}
Exit:
	log.Debug("stop monitoring firewall config file")
	c.Lock()
	c.monitorExitChan = nil
	c.Unlock()
}

// MonitorSystemFw waits for configuration reloads.
func (c *Config) MonitorSystemFw(reloadCallback callback) {
	for {
		select {
		case reload := <-c.ReloadConfChan:
			if reload {
				reloadCallback()
			} else {
				goto Exit
			}
		}
	}
Exit:
	log.Info("iptables, stop monitoring system fw rules")
	c.Lock()
	c.ReloadConfChan = nil
	c.Unlock()
}
