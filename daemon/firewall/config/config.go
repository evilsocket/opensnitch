// Package config provides functionality to load and monitor the system
// firewall rules.
// It's inherited by the different firewall packages (iptables, nftables).
//
// The firewall rules defined by the user are reloaded in these cases:
// - When the file system-fw.json changes.
// - When the firewall rules are not present when listing them.
package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/fsnotify/fsnotify"
)

// ExprValues holds the statements' options:
// "Name": "ct",
// "Values": [
// {
//   "Key":   "state",
//   "Value": "established"
// },
// {
//   "Key":   "state",
//   "Value": "related"
// }]
type ExprValues struct {
	Key   string
	Value string
}

// ExprStatement holds the definition of matches to use against connections.
//{
//	"Op": "!=",
//	"Name": "tcp",
//	"Values": [
//		{
//			"Key": "dport",
// 			"Value": "443"
//		}
//	]
//}
type ExprStatement struct {
	Op     string        // ==, !=, ... Only one per expression set.
	Name   string        // tcp, udp, ct, daddr, log, ...
	Values []*ExprValues // dport 8000
}

// Expressions holds the array of expressions that create the rules
type Expressions struct {
	Statement *ExprStatement
}

// FwRule holds the fields of a rule
type FwRule struct {
	*sync.RWMutex
	// we need to keep old fields in the struct. Otherwise when receiving a conf from the GUI, the legacy rules would be deleted.
	Chain            string // TODO: deprecated, remove
	Table            string // TODO: deprecated, remove
	Parameters       string // TODO: deprecated, remove
	UUID             string
	Description      string
	Target           string
	TargetParameters string
	Expressions      []*Expressions
	Position         uint64 `json:",string"`
	Enabled          bool
}

// FwChain holds the information that defines a firewall chain.
// It also contains the firewall table definition that it belongs to.
type FwChain struct {
	// table fields
	Table  string
	Family string
	// chain fields
	Name        string
	Description string
	Priority    string
	Type        string
	Hook        string
	Policy      string
	Rules       []*FwRule
}

// IsInvalid checks if the chain has been correctly configured.
func (fc *FwChain) IsInvalid() bool {
	return fc.Name == "" || fc.Family == "" || fc.Table == ""
}

type rulesList struct {
	Rule *FwRule
}

type chainsList struct {
	Rule   *FwRule // TODO: deprecated, remove
	Chains []*FwChain
}

// SystemConfig holds the list of rules to be added to the system
type SystemConfig struct {
	SystemRules []*chainsList
	sync.RWMutex
	Version uint32
	Enabled bool
}

// Config holds the functionality to re/load the firewall configuration from disk.
// This is the configuration to manage the system firewall (iptables, nftables).
type Config struct {
	watcher         *fsnotify.Watcher
	monitorExitChan chan bool
	// preloadCallback is called before reloading the configuration,
	// in order to delete old fw rules.
	preloadCallback func()
	// reloadCallback is called after the configuration is written.
	reloadCallback func()
	// preload will be called after daemon startup, whilst reload when a modification is performed.
	file      string
	SysConfig SystemConfig
	sync.Mutex
}

// NewSystemFwConfig initializes config fields
func (c *Config) NewSystemFwConfig(configPath string, preLoadCb, reLoadCb func()) (*Config, error) {
	var err error
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warning("Error creating firewall config watcher: %s", err)
		return nil, err
	}

	c.Lock()
	defer c.Unlock()

	c.file = configPath
	c.monitorExitChan = make(chan bool, 1)
	c.preloadCallback = preLoadCb
	c.reloadCallback = reLoadCb
	c.watcher = watcher
	return c, nil
}

// SetConfigFile sets the absolute path to the configuration file to use.
// If it's empty, it'll be ignored (when changing the fw type for example).
func (c *Config) SetConfigFile(file string) {
	if file == "" {
		log.Debug("Firewall configuration file not provided, ignoring")
		return
	}
	c.file = file
}

// LoadDiskConfiguration reads and loads the firewall configuration from disk
func (c *Config) LoadDiskConfiguration(reload bool) error {
	c.Lock()
	defer c.Unlock()

	raw, err := ioutil.ReadFile(c.file)
	if err != nil {
		log.Error("Error reading firewall configuration from disk %s: %s", c.file, err)
		return err
	}

	if err = c.loadConfiguration(raw); err != nil {
		return err
	}
	// we need to monitor the configuration file for changes, regardless if it's
	// malformed or not.
	c.watcher.Remove(c.file)
	if err := c.watcher.Add(c.file); err != nil {
		log.Error("Could not watch firewall configuration: %s", err)
		return err
	}

	if reload {
		c.reloadCallback()
		return nil
	}

	go c.monitorConfigWorker()

	return nil
}

// loadConfigutation reads the system firewall rules from disk.
// Then the rules are added based on the configuration defined.
func (c *Config) loadConfiguration(rawConfig []byte) error {
	c.SysConfig.Lock()
	defer c.SysConfig.Unlock()

	// delete old system rules, that may be different from the new ones
	c.preloadCallback()

	if err := json.Unmarshal(rawConfig, &c.SysConfig); err != nil {
		// we only log the parser error, giving the user a chance to write a valid config
		log.Error("Error parsing firewall configuration %s: %s", c.file, err)
		return err
	}
	log.Info("fw configuration loaded")

	return nil
}

// SaveConfiguration saves configuration to disk.
// This event dispatches a reload of the configuration.
func (c *Config) SaveConfiguration(rawConfig string) error {
	conf, err := json.MarshalIndent([]byte(rawConfig), "  ", "  ")
	if err != nil {
		log.Error("saving json firewall configuration: %s %s", err, conf)
		return err
	}

	if err = os.Chmod(c.file, 0600); err != nil {
		log.Warning("unable to set system-fw.json permissions: %s", err)
	}
	if err = ioutil.WriteFile(c.file, []byte(rawConfig), 0600); err != nil {
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
				c.LoadDiskConfiguration(common.ReloadConf)
			}
		}
	}
Exit:
	log.Debug("stop monitoring firewall config file")
	c.Lock()
	c.monitorExitChan = nil
	c.Unlock()
}
