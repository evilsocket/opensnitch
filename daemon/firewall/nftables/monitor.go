package nftables

import (
	"time"

	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
)

// AreRulesLoaded checks if the firewall rules for intercept traffic are loaded.
func (n *Nft) AreRulesLoaded() bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	nRules := 0
	chains, err := n.conn.ListChains()
	if err != nil {
		log.Warning("[nftables] error listing nftables chains: %s", err)
		return false
	}

	for _, c := range chains {
		rules, err := n.conn.GetRule(c.Table, c)
		if err != nil {
			log.Warning("[nftables] Error listing rules: %s", err)
			continue
		}
		for rdx, r := range rules {
			if string(r.UserData) == interceptionRuleKey {
				nRules++
				if c.Table.Name == exprs.NFT_CHAIN_MANGLE && rdx+1 != len(rules) {
					log.Warning("nfables queue rule is not the latest of the list, reloading")
					return false
				}
			}
		}
	}
	// we expect to have exactly 2 rules (queue and dns). If there're less or more, then we
	// need to reload them.
	if nRules != 2 {
		log.Warning("nfables filter rules not loaded: %d", nRules)
		return false
	}

	return true
}

// reloadConfCallback gets called after the configuration changes.
func (n *Nft) reloadConfCallback() {
	log.Important("reloadConfCallback changed, reloading")
	n.DeleteSystemRules(!common.ForcedDelRules, !common.RestoreChains, log.GetLogLevel() == log.DEBUG)
	n.AddSystemRules(common.ReloadRules, !common.BackupChains)
}

// reloadRulesCallback gets called when the interception rules are not present.
func (n *Nft) reloadRulesCallback() {
	log.Important("nftables firewall rules changed, reloading")
	n.DisableInterception(log.GetLogLevel() == log.DEBUG)
	time.Sleep(time.Millisecond * 500)
	n.EnableInterception()
}

// preloadConfCallback gets called before the fw configuration is loaded
func (n *Nft) preloadConfCallback() {
	log.Info("nftables config changed, reloading")
	n.DeleteSystemRules(!common.ForcedDelRules, common.RestoreChains, log.GetLogLevel() == log.DEBUG)
}
