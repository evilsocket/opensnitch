package firewall

import (
	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/iptables"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables"
	"github.com/evilsocket/opensnitch/daemon/log"
)

// Firewall is the interface that all firewalls (iptables, nftables) must implement.
type Firewall interface {
	Init(*int)
	Stop()
	Name() string
	IsRunning() bool
	SetQueueNum(num *int)

	InsertRules()
	QueueDNSResponses(bool, bool) (error, error)
	QueueConnections(bool, bool) (error, error)
	CleanRules(bool)

	AddSystemRules()
	DeleteSystemRules(bool, bool)
	AddSystemRule(*config.FwRule, bool) (error, error)
	CreateSystemRule(*config.FwRule, bool)
}

var fw Firewall

// Determine as soon as possible what firewall to use.
func init() {
	var err error
	fw, err = iptables.Fw()
	if err != nil {
		log.Warning("iptables not available: %s", err)
		fw, err = nftables.Fw()
	}

	if err != nil {
		log.Warning("firewall error: %s, not iptables nor nftables are available or are usable. Please, report it on github.", err)
	}
}

// IsRunning returns if the firewall is running or not.
func IsRunning() bool {
	return fw != nil && fw.IsRunning()
}

// CleanRules deletes the rules we added.
func CleanRules(logErrors bool) {
	fw.CleanRules(logErrors)
}

// Stop deletes the firewall rules, allowing network traffic.
func Stop() {
	fw.Stop()
}

// Init initializes the firewall and loads firewall rules.
func Init(qNum *int) {
	if fw == nil {
		log.Error("firewall not initialized.")
		return
	}
	fw.Init(qNum)

	log.Info("Using %s firewall", fw.Name())
}
