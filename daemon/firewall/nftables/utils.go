package nftables

import (
	"strings"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
)

func GetFamilyCode(family string) nftables.TableFamily {
	famCode := nftables.TableFamilyINet
	switch family {
	// [filter]: prerouting	forward	input	output	postrouting
	// [nat]: prerouting, input	output	postrouting
	// [route]: output
	case exprs.NFT_FAMILY_IP6:
		famCode = nftables.TableFamilyIPv6
	case exprs.NFT_FAMILY_IP:
		famCode = nftables.TableFamilyIPv4
	case exprs.NFT_FAMILY_BRIDGE:
		// [filter]: prerouting	forward	input	output	postrouting
		famCode = nftables.TableFamilyBridge
	case exprs.NFT_FAMILY_ARP:
		// [filter]: input	output
		famCode = nftables.TableFamilyARP
	case exprs.NFT_FAMILY_NETDEV:
		// [filter]: egress, ingress
		famCode = nftables.TableFamilyNetdev
	}

	return famCode
}

func GetHook(chain string) *nftables.ChainHook {
	hook := nftables.ChainHookOutput

	// https://github.com/google/nftables/blob/master/chain.go#L33
	switch strings.ToLower(chain) {
	case exprs.NFT_HOOK_INPUT:
		hook = nftables.ChainHookInput
	case exprs.NFT_HOOK_PREROUTING:
		hook = nftables.ChainHookPrerouting
	case exprs.NFT_HOOK_POSTROUTING:
		hook = nftables.ChainHookPostrouting
	case exprs.NFT_HOOK_FORWARD:
		hook = nftables.ChainHookForward
	case exprs.NFT_HOOK_INGRESS:
		hook = nftables.ChainHookIngress
	}

	return hook
}

// GetChainPriority gets the corresponding priority for the given chain, based
// on the following configuration matrix:
// https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks#Priority_within_hook
// https://github.com/google/nftables/blob/master/chain.go#L48
// man nft (table 6.)
func GetChainPriority(family, cType, hook string) (*nftables.ChainPriority, nftables.ChainType) {
	// types: route, nat, filter
	chainType := nftables.ChainTypeFilter
	// priorities: raw, conntrack, mangle, natdest, filter, security
	chainPrio := nftables.ChainPriorityFilter

	family = strings.ToLower(family)
	cType = strings.ToLower(cType)
	hook = strings.ToLower(hook)

	// constraints
	// https://www.netfilter.org/projects/nftables/manpage.html#lbAQ
	if (cType == exprs.NFT_CHAIN_NATDEST || cType == exprs.NFT_CHAIN_NATSOURCE) && hook == exprs.NFT_HOOK_FORWARD {
		log.Warning("[nftables] invalid nat combination of tables and hooks. chain: %s, hook: %s", cType, hook)
		return nil, chainType
	}
	if family == exprs.NFT_FAMILY_NETDEV && (cType != exprs.NFT_CHAIN_FILTER || hook != exprs.NFT_HOOK_INGRESS) {
		log.Warning("[nftables] invalid netdev combination of tables and hooks. chain: %s, hook: %s", cType, hook)
		return nil, chainType
	}
	if family == exprs.NFT_FAMILY_ARP && (cType != exprs.NFT_CHAIN_FILTER || (hook != exprs.NFT_HOOK_OUTPUT && hook != exprs.NFT_HOOK_INPUT)) {
		log.Warning("[nftables] invalid arp combination of tables and hooks. chain: %s, hook: %s", cType, hook)
		return nil, chainType
	}
	if family == exprs.NFT_FAMILY_BRIDGE && (cType != exprs.NFT_CHAIN_FILTER || (hook == exprs.NFT_HOOK_EGRESS || hook == exprs.NFT_HOOK_INGRESS)) {
		log.Warning("[nftables] invalid bridge combination of tables and hooks. chain: %s, hook: %s", cType, hook)
		return nil, chainType
	}

	// Standard priority names, family and hook compatibility matrix
	// https://www.netfilter.org/projects/nftables/manpage.html#lbAQ

	switch cType {
	case exprs.NFT_CHAIN_FILTER:
		if family == exprs.NFT_FAMILY_BRIDGE {
			// bridge	all	filter	-200	NF_BR_PRI_FILTER_BRIDGED
			chainPrio = nftables.ChainPriorityConntrack
			switch hook {
			case exprs.NFT_HOOK_PREROUTING: // -300
				chainPrio = nftables.ChainPriorityRaw
			case exprs.NFT_HOOK_OUTPUT: // -100
				chainPrio = nftables.ChainPriorityNATSource
			case exprs.NFT_HOOK_POSTROUTING: // 300
				chainPrio = nftables.ChainPriorityConntrackHelper
			}
		}
	case exprs.NFT_CHAIN_MANGLE:
		// hooks: all
		// XXX: check hook input?
		chainPrio = nftables.ChainPriorityMangle
		// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_types
		// (...) equivalent semantics to the mangle table but only for the output hook (for other hooks use type filter instead).

		// Despite of what is said on the wiki, mangle chains must be of filter type,
		// otherwise on some kernels (4.19.x) table MANGLE hook OUTPUT chain is not created
		chainType = nftables.ChainTypeFilter

	case exprs.NFT_CHAIN_RAW:
		// hook: all
		chainPrio = nftables.ChainPriorityRaw

	case exprs.NFT_CHAIN_CONNTRACK:
		chainPrio, chainType = GetConntrackPriority(hook)

	case exprs.NFT_CHAIN_NATDEST:
		// hook: prerouting
		chainPrio = nftables.ChainPriorityNATDest
		switch hook {
		case exprs.NFT_HOOK_OUTPUT:
			chainPrio = nftables.ChainPriorityNATSource
		}
		chainType = nftables.ChainTypeNAT

	case exprs.NFT_CHAIN_NATSOURCE:
		// hook: postrouting
		chainPrio = nftables.ChainPriorityNATSource
		chainType = nftables.ChainTypeNAT

	case exprs.NFT_CHAIN_SECURITY:
		// hook: all
		chainPrio = nftables.ChainPrioritySecurity

	case exprs.NFT_CHAIN_SELINUX:
		// hook: all
		if hook != exprs.NFT_HOOK_POSTROUTING {
			chainPrio = nftables.ChainPrioritySELinuxLast
		} else {
			chainPrio = nftables.ChainPrioritySELinuxFirst
		}
	}

	return chainPrio, chainType
}

// https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks#Priority_within_hook
func GetConntrackPriority(hook string) (*nftables.ChainPriority, nftables.ChainType) {
	chainType := nftables.ChainTypeFilter
	chainPrio := nftables.ChainPriorityConntrack
	switch hook {
	case exprs.NFT_HOOK_PREROUTING:
		chainPrio = nftables.ChainPriorityConntrack
		// ChainTypeNAT not allowed here
	case exprs.NFT_HOOK_OUTPUT:
		chainPrio = nftables.ChainPriorityNATSource // 100 - ChainPriorityConntrack
	case exprs.NFT_HOOK_POSTROUTING:
		chainPrio = nftables.ChainPriorityConntrackHelper
		chainType = nftables.ChainTypeNAT
	case exprs.NFT_HOOK_INPUT:
		// can also be hook == NFT_HOOK_POSTROUTING
		chainPrio = nftables.ChainPriorityConntrackConfirm
	}

	return chainPrio, chainType
}
