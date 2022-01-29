package nftables

import (
	"github.com/evilsocket/opensnitch/daemon/log"
)

// AreRulesLoaded checks if the firewall rules for intercept traffic are loaded.
func (n *Nft) AreRulesLoaded() bool {
	n.Lock()
	defer n.Unlock()

	nRules := 0
	for _, table := range n.mangleTables {
		rules, err := n.conn.GetRule(table, n.outputChains[table])
		if err != nil {
			log.Error("nftables mangle rules error: %s, %s", table.Name, n.outputChains[table].Name)
			return false
		}
		for _, r := range rules {
			if string(r.UserData) == fwKey {
				nRules++
			}
		}
	}
	if nRules != 2 {
		log.Warning("nftables mangle rules not loaded: %d", nRules)
		return false
	}

	nRules = 0
	for _, table := range n.filterTables {
		rules, err := n.conn.GetRule(table, n.inputChains[table])
		if err != nil {
			log.Error("nftables filter rules error: %s, %s", table.Name, n.inputChains[table].Name)
			return false
		}
		for _, r := range rules {
			if string(r.UserData) == fwKey {
				nRules++
			}
		}
	}
	if nRules != 2 {
		log.Warning("nfables filter rules not loaded: %d", nRules)
		return false
	}

	return true
}

func (n *Nft) reloadRulesCallback() {
	log.Important("nftables firewall rules changed, reloading")
	n.AddSystemRules()
	n.InsertRules()
}
