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
		ch  chan bool
		rwm sync.RWMutex
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
		rwm             sync.RWMutex
	}
)

func (s *stopChecker) exit() <-chan bool {
	s.rwm.RLock()
	defer s.rwm.RUnlock()
	return s.ch
}

func (s *stopChecker) stop() {
	s.rwm.Lock()
	defer s.rwm.Unlock()

	if s.ch != nil {
		s.ch <- true
		close(s.ch)
		s.ch = nil
	}
}

// SetQueueNum sets the queue number used by the firewall.
// It's the queue where all intercepted connections will be sent.
func (c *Common) SetQueueNum(qNum *int) {
	c.rwm.Lock()
	defer c.rwm.Unlock()

	if qNum != nil {
		c.QueueNum = uint16(*qNum)
	}

}

// IsRunning returns if the firewall is running or not.
func (c *Common) IsRunning() bool {
	c.rwm.RLock()
	defer c.rwm.RUnlock()

	return c != nil && c.Running
}

// IsFirewallEnabled returns if the firewall is running or not.
func (c *Common) IsFirewallEnabled() bool {
	c.rwm.RLock()
	defer c.rwm.RUnlock()

	return c != nil && c.FwEnabled
}

// IsIntercepting returns if the firewall is running or not.
func (c *Common) IsIntercepting() bool {
	c.rwm.RLock()
	defer c.rwm.RUnlock()

	return c != nil && c.Intercepting
}

// NewRulesChecker starts monitoring interception rules.
// We expect to have 2 rules loaded: one to intercept DNS responses and another one
// to intercept network traffic.
func (c *Common) NewRulesChecker(areRulesLoaded callbackBool, reloadRules callback) {
	c.rwm.Lock()
	defer c.rwm.Unlock()
	if c.stopCheckerChan != nil {
		c.stopCheckerChan.stop()
		c.stopCheckerChan = nil
	}

	c.stopCheckerChan = &stopChecker{ch: make(chan bool, 1)}
	if c.RulesChecker != nil {
		c.stopCheckerChan.stop()
		c.RulesChecker.Stop()
	}
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
	c.rwm.RLock()
	defer c.rwm.RUnlock()

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
