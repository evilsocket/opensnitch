package common

import (
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
)

// default arguments for various functions
var (
	EnableRule     = true
	DoLogErrors    = true
	ForcedDelRules = true
	ReloadRules    = true
	RestoreChains  = true
	BackupChains   = true
	ReloadConf     = true
)

type (
	callback     func()
	callbackBool func() bool

	stopChecker struct {
		ch chan bool
		sync.RWMutex
	}

	// Common holds common fields and functionality of both firewalls,
	// iptables and nftables.
	Common struct {
		RulesChecker    *time.Ticker
		stopCheckerChan *stopChecker
		QueueNum        uint16
		Running         bool
		Intercepting    bool
		FwEnabled       bool
		sync.RWMutex
	}
)

func (s *stopChecker) exit() <-chan bool {
	s.RLock()
	defer s.RUnlock()
	return s.ch
}

func (s *stopChecker) stop() {
	s.Lock()
	defer s.Unlock()

	if s.ch != nil {
		s.ch <- true
		close(s.ch)
		s.ch = nil
	}
}

// SetQueueNum sets the queue number used by the firewall.
// It's the queue where all intercepted connections will be sent.
func (c *Common) SetQueueNum(qNum *int) {
	c.Lock()
	defer c.Unlock()

	if qNum != nil {
		c.QueueNum = uint16(*qNum)
	}

}

// IsRunning returns if the firewall is running or not.
func (c *Common) IsRunning() bool {
	c.RLock()
	defer c.RUnlock()

	return c != nil && c.Running
}

// IsFirewallEnabled returns if the firewall is running or not.
func (c *Common) IsFirewallEnabled() bool {
	c.RLock()
	defer c.RUnlock()

	return c != nil && c.FwEnabled
}

// IsIntercepting returns if the firewall is running or not.
func (c *Common) IsIntercepting() bool {
	c.RLock()
	defer c.RUnlock()

	return c != nil && c.Intercepting
}

// NewRulesChecker starts monitoring interception rules.
// We expect to have 2 rules loaded: one to intercept DNS responses and another one
// to intercept network traffic.
func (c *Common) NewRulesChecker(areRulesLoaded callbackBool, reloadRules callback) {
	c.Lock()
	defer c.Unlock()
	if c.stopCheckerChan != nil {
		c.stopCheckerChan.stop()
		c.stopCheckerChan = nil
	}

	c.stopCheckerChan = &stopChecker{ch: make(chan bool, 1)}
	c.RulesChecker = time.NewTicker(time.Second * 15)

	go c.startCheckingRules(areRulesLoaded, reloadRules)
}

// StartCheckingRules monitors if our rules are loaded.
// If the rules to intercept traffic are not loaded, we'll try to insert them again.
func (c *Common) startCheckingRules(areRulesLoaded callbackBool, reloadRules callback) {
	for {
		select {
		case <-c.stopCheckerChan.exit():
			goto Exit
		case <-c.RulesChecker.C:
			if areRulesLoaded() == false {
				reloadRules()
			}
		}
	}

Exit:
	log.Info("exit checking firewall rules")
}

// StopCheckingRules stops checking if firewall rules are loaded.
func (c *Common) StopCheckingRules() {
	c.RLock()
	defer c.RUnlock()

	if c.RulesChecker != nil {
		c.RulesChecker.Stop()
	}
	if c.stopCheckerChan != nil {
		c.stopCheckerChan.stop()
	}
}

func (c *Common) reloadCallback(callback func()) {
	callback()
}
