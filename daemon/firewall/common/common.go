package common

import (
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
)

type (
	callback     func()
	callbackBool func() bool

	stopChecker struct {
		sync.RWMutex
		ch chan bool
	}

	// Common holds common fields and functionality of both firewalls,
	// iptables and nftables.
	Common struct {
		sync.RWMutex
		QueueNum        uint16
		Running         bool
		RulesChecker    *time.Ticker
		stopCheckerChan *stopChecker
	}
)

func (s *stopChecker) exit() chan bool {
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

// NewRulesChecker starts monitoring firewall for configuration or rules changes.
func (c *Common) NewRulesChecker(areRulesLoaded callbackBool, reloadRules callback) {
	c.Lock()
	defer c.Unlock()

	c.stopCheckerChan = &stopChecker{ch: make(chan bool, 1)}
	c.RulesChecker = time.NewTicker(time.Second * 30)

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
	log.Info("exit checking iptables rules")
}

// StopCheckingRules stops checking if firewall rules are loaded.
func (c *Common) StopCheckingRules() {
	if c.RulesChecker != nil {
		c.RulesChecker.Stop()
	}
	c.stopCheckerChan.stop()
}
