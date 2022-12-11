package nftables

import (
	"fmt"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
)

// AddChain adds a new chain to nftables.
// https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks#Priority_within_hook
func (n *Nft) AddChain(name, table, family string, priority nftables.ChainPriority, ctype nftables.ChainType, hook nftables.ChainHook, policy nftables.ChainPolicy) *nftables.Chain {
	if family == "" {
		family = exprs.NFT_FAMILY_INET
	}
	tbl := getTable(table, family)
	if tbl == nil {
		log.Error("%s addChain, Error getting table: %s, %s", logTag, table, family)
		return nil
	}

	// nft list chains
	chain := n.conn.AddChain(&nftables.Chain{
		Name:     strings.ToLower(name),
		Table:    tbl,
		Type:     ctype,
		Hooknum:  hook,
		Priority: priority,
		Policy:   &policy,
	})
	if chain == nil {
		return nil
	}

	key := getChainKey(name, tbl)
	sysChains[key] = chain
	return chain
}

// getChainKey returns the identifier that will be used to link chains and rules.
// When adding a new chain the key is stored, then later when adding a rule we get
// the chain that the rule belongs to by this key.
func getChainKey(name string, table *nftables.Table) string {
	if table == nil {
		return ""
	}
	return fmt.Sprintf("%s-%s-%d", name, table.Name, table.Family)
}

// get an existing chain
func getChain(name string, table *nftables.Table) *nftables.Chain {
	key := getChainKey(name, table)
	return sysChains[key]
}

// regular chains are user-defined chains, to better organize fw rules.
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Adding_regular_chains
func (n *Nft) addRegularChain(name, table, family string) error {
	tbl := getTable(table, family)
	if tbl == nil {
		return fmt.Errorf("%s addRegularChain, Error getting table: %s, %s", logTag, table, family)
	}

	chain := n.conn.AddChain(&nftables.Chain{
		Name:  name,
		Table: tbl,
	})
	if chain == nil {
		return fmt.Errorf("%s error adding regular chain: %s", logTag, name)
	}
	key := getChainKey(name, tbl)
	sysChains[key] = chain

	return nil
}

func (n *Nft) addInterceptionChains() error {
	var filterPolicy nftables.ChainPolicy
	var manglePolicy nftables.ChainPolicy
	filterPolicy = nftables.ChainPolicyAccept
	manglePolicy = nftables.ChainPolicyAccept

	tbl := getTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
	if tbl != nil {
		key := getChainKey(exprs.NFT_HOOK_INPUT, tbl)
		if key != "" && sysChains[key] != nil {
			filterPolicy = *sysChains[key].Policy
		}
	}
	tbl = getTable(exprs.NFT_CHAIN_MANGLE, exprs.NFT_FAMILY_INET)
	if tbl != nil {
		key := getChainKey(exprs.NFT_HOOK_OUTPUT, tbl)
		if key != "" && sysChains[key] != nil {
			manglePolicy = *sysChains[key].Policy
		}
	}

	// nft list tables
	n.AddChain(exprs.NFT_HOOK_INPUT, exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET,
		nftables.ChainPriorityFilter, nftables.ChainTypeFilter, nftables.ChainHookInput, filterPolicy)
	n.AddChain(exprs.NFT_HOOK_OUTPUT, exprs.NFT_CHAIN_MANGLE, exprs.NFT_FAMILY_INET,
		nftables.ChainPriorityMangle, nftables.ChainTypeRoute, nftables.ChainHookOutput, manglePolicy)

	// apply changes
	if !n.Commit() {
		return fmt.Errorf("Error adding interception chains")
	}

	return nil
}

func (n *Nft) delChain(chain *nftables.Chain) error {
	n.conn.DelChain(chain)
	delete(sysChains, getChainKey(chain.Name, chain.Table))
	if !n.Commit() {
		return fmt.Errorf("[nftables] error deleting chain %s, %s", chain.Name, chain.Table.Name)
	}

	return nil
}
