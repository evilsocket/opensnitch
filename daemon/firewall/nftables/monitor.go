package nftables

import (
	"time"

	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
)

// AreRulesLoaded checks if the firewall rules for intercept traffic are loaded.
func (n *Nft) AreRulesLoaded() bool {
	n.Lock()
	defer n.Unlock()

	nRules := 0
	chains, err := n.Conn.ListChains()
	if err != nil {
		log.Warning("[nftables] error listing nftables chains: %s", err)
		return false
	}

	for _, c := range chains {
		rules, err := n.Conn.GetRule(c.Table, c)
		if err != nil {
			log.Warning("[nftables] Error listing rules: %s", err)
			continue
		}
		for rdx, r := range rules {
			if string(r.UserData) == InterceptionRuleKey {
				if c.Table.Name == exprs.NFT_CHAIN_FILTER && c.Name == exprs.NFT_HOOK_INPUT && rdx != 0 {
					log.Warning("nftables DNS rule not in 1st position (%d)", rdx)
					return false
				}
				nRules++
				if c.Table.Name == exprs.NFT_CHAIN_MANGLE && rdx < len(rules)-2 {
					log.Warning("nfables queue rule is not the latest of the list (%d/%d), reloading", rdx, len(rules))
					return false
				}
			}
		}
	}
	// we expect to have exactly 3 rules (2 queue and 1 dns). If there're less or more, then we
	// need to reload them.
	if nRules != 3 {
		log.Warning("nfables filter rules not loaded: %d", nRules)
		return false
	}

	return true
}

// ReloadConfCallback gets called after the configuration changes.
func (n *Nft) ReloadConfCallback() {
	log.Important("reloadConfCallback changed, reloading")
	n.DeleteSystemRules(!common.ForcedDelRules, !common.RestoreChains, log.GetLogLevel() == log.DEBUG)
	n.AddSystemRules(common.ReloadRules, !common.BackupChains)
}

// ReloadRulesCallback gets called when the interception rules are not present.
func (n *Nft) ReloadRulesCallback() {
	log.Important("nftables firewall rules changed, reloading")
	n.DisableInterception(log.GetLogLevel() == log.DEBUG)
	time.Sleep(time.Millisecond * 500)
	n.EnableInterception()
}

// PreloadConfCallback gets called before the fw configuration is loaded
func (n *Nft) PreloadConfCallback() {
	log.Info("nftables config changed, reloading")
	n.DeleteSystemRules(!common.ForcedDelRules, common.RestoreChains, log.GetLogLevel() == log.DEBUG)
}
