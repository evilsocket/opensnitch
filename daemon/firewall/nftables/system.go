package nftables

import (
	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/log"
)

// CreateSystemRule create the custom firewall chains and adds them to system.
// nft insert rule ip opensnitch-filter opensnitch-input udp dport 1153
func (n *Nft) CreateSystemRule(rule *config.FwRule, logErrors bool) {
	// TODO
}

// DeleteSystemRules deletes the system rules.
// If force is false and the rule has not been previously added,
// it won't try to delete the rules. Otherwise it'll try to delete them.
func (n *Nft) DeleteSystemRules(force, logErrors bool) {
	// TODO
}

// AddSystemRule inserts a new rule.
func (n *Nft) AddSystemRule(rule *config.FwRule, enable bool) (error, error) {
	// TODO
	return nil, nil
}

// AddSystemRules creates the system firewall from configuration
func (n *Nft) AddSystemRules() {
	n.DeleteSystemRules(true, false)

	for _, r := range n.SysConfig.SystemRules {
		n.CreateSystemRule(r.Rule, true)
		n.AddSystemRule(r.Rule, true)
	}
}

// preloadConfCallback gets called before the fw configuration is reloaded
func (n *Nft) preloadConfCallback() {
	n.DeleteSystemRules(true, log.GetLogLevel() == log.DEBUG)
}
