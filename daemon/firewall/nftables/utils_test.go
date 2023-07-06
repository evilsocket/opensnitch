package nftables_test

import (
	"testing"

	nftb "github.com/evilsocket/opensnitch/daemon/firewall/nftables"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/google/nftables"
)

type chainPrioT struct {
	test        string
	errorReason string
	family      string
	chain       string
	hook        string
	checkEqual  bool
	chainPrio   *nftables.ChainPriority
	chainType   nftables.ChainType
}

// TestGetConntrackPriority test basic Conntrack chains priority configurations.
// https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks#Priority_within_hook
func TestGetConntrackPriority(t *testing.T) {

	t.Run("hook-prerouting", func(t *testing.T) {
		cprio, ctype := nftb.GetConntrackPriority(exprs.NFT_HOOK_PREROUTING)
		if cprio != nftables.ChainPriorityConntrack && ctype != nftables.ChainTypeFilter {
			t.Errorf("invalid conntrack priority or type for hook PREROUTING: %+v, %+v", cprio, ctype)
		}
	})

	t.Run("hook-output", func(t *testing.T) {
		cprio, ctype := nftb.GetConntrackPriority(exprs.NFT_HOOK_OUTPUT)
		if cprio != nftables.ChainPriorityNATSource && ctype != nftables.ChainTypeFilter {
			t.Errorf("invalid conntrack priority or type for hook OUTPUT: %+v, %+v", cprio, ctype)
		}
	})

	t.Run("hook-postrouting", func(t *testing.T) {
		cprio, ctype := nftb.GetConntrackPriority(exprs.NFT_HOOK_POSTROUTING)
		if cprio != nftables.ChainPriorityConntrackHelper && ctype != nftables.ChainTypeNAT {
			t.Errorf("invalid conntrack priority or type for hook POSTROUTING: %+v, %+v", cprio, ctype)
		}
	})

	t.Run("hook-input", func(t *testing.T) {
		cprio, ctype := nftb.GetConntrackPriority(exprs.NFT_HOOK_INPUT)
		if cprio != nftables.ChainPriorityConntrackConfirm && ctype != nftables.ChainTypeFilter {
			t.Errorf("invalid conntrack priority or type for hook INPUT: %+v, %+v", cprio, ctype)
		}
	})

}

// https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks#Priority_within_hook
// https://github.com/google/nftables/blob/master/chain.go#L48
// man nft (table 6.)
func TestGetChainPriority(t *testing.T) {
	matrixTests := []chainPrioT{
		// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_types
		// (...) equivalent semantics to the mangle table but only for the output hook (for other hooks use type filter instead).

		// Despite of what is said on the wiki, mangle chains must be of filter type,
		// otherwise on some kernels (4.19.x) table MANGLE hook OUTPUT chain is not created
		{
			"inet-mangle-output",
			"invalid MANGLE chain priority or type: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_INET, exprs.NFT_CHAIN_MANGLE, exprs.NFT_HOOK_OUTPUT,
			true,
			nftables.ChainPriorityMangle, nftables.ChainTypeFilter,
		},
		{
			"inet-natdest-output",
			"invalid NATDest-output chain priority or type: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_INET, exprs.NFT_CHAIN_NATDEST, exprs.NFT_HOOK_OUTPUT,
			true,
			nftables.ChainPriorityNATSource, nftables.ChainTypeNAT,
		},
		{
			"inet-natdest-prerouting",
			"invalid NATDest-prerouting chain priority or type: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_INET, exprs.NFT_CHAIN_NATDEST, exprs.NFT_HOOK_PREROUTING,
			true,
			nftables.ChainPriorityNATDest, nftables.ChainTypeNAT,
		},
		{
			"inet-natsource-postrouting",
			"invalid NATSource-postrouting chain priority or type: %+v-%+v, %v-%v",
			exprs.NFT_FAMILY_INET, exprs.NFT_CHAIN_NATSOURCE, exprs.NFT_HOOK_POSTROUTING,
			true,
			nftables.ChainPriorityNATSource, nftables.ChainTypeNAT,
		},

		// constraints
		// https://www.netfilter.org/projects/nftables/manpage.html#lbAQ
		{
			"inet-natdest-forward",
			"invalid natdest-forward chain: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_INET, exprs.NFT_CHAIN_NATDEST, exprs.NFT_HOOK_FORWARD,
			true,
			nil, nftables.ChainTypeFilter,
		},
		{
			"inet-natsource-forward",
			"invalid natsource-forward chain: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_INET, exprs.NFT_CHAIN_NATSOURCE, exprs.NFT_HOOK_FORWARD,
			true,
			nil, nftables.ChainTypeFilter,
		},
		{
			"netdev-filter-ingress",
			"invalid netdev chain prio or type: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_NETDEV, exprs.NFT_CHAIN_FILTER, exprs.NFT_HOOK_INGRESS,
			true,
			nftables.ChainPriorityFilter, nftables.ChainTypeFilter,
		},
		{
			"arp-filter-input",
			"invalid arp chain prio or type: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_ARP, exprs.NFT_CHAIN_FILTER, exprs.NFT_HOOK_INPUT,
			true,
			nftables.ChainPriorityFilter, nftables.ChainTypeFilter,
		},
		{
			"bridge-filter-prerouting",
			"invalid bridge-prerouting chain prio or type: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_BRIDGE, exprs.NFT_CHAIN_FILTER, exprs.NFT_HOOK_PREROUTING,
			true,
			nftables.ChainPriorityRaw, nftables.ChainTypeFilter,
		},
		{
			"bridge-filter-output",
			"invalid bridge-output chain prio or type: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_BRIDGE, exprs.NFT_CHAIN_FILTER, exprs.NFT_HOOK_OUTPUT,
			true,
			nftables.ChainPriorityNATSource, nftables.ChainTypeFilter,
		},
		{
			"bridge-filter-postrouting",
			"invalid bridge-postrouting chain prio or type: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_BRIDGE, exprs.NFT_CHAIN_FILTER, exprs.NFT_HOOK_POSTROUTING,
			true,
			nftables.ChainPriorityConntrackHelper, nftables.ChainTypeFilter,
		},
	}

	for _, testChainPrio := range matrixTests {
		t.Run(testChainPrio.test, func(t *testing.T) {
			chainPrio, chainType := nftb.GetChainPriority(testChainPrio.family, testChainPrio.chain, testChainPrio.hook)

			if testChainPrio.checkEqual {
				if chainPrio != testChainPrio.chainPrio && chainType != testChainPrio.chainType {
					t.Errorf(testChainPrio.errorReason, chainPrio, chainType, testChainPrio.chainPrio, testChainPrio.chainType)
				}
			} else {
				if chainPrio == testChainPrio.chainPrio && chainType == testChainPrio.chainType {
					t.Errorf(testChainPrio.errorReason, chainPrio, chainType, testChainPrio.chainPrio, testChainPrio.chainType)
				}
			}
		})
	}

}

func TestInvalidChainPriority(t *testing.T) {
	matrixTests := []chainPrioT{
		{
			"inet-natdest-forward",
			"natdest-forward chain should be invalid: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_INET, exprs.NFT_CHAIN_NATDEST, exprs.NFT_HOOK_FORWARD,
			true,
			nil, nftables.ChainTypeFilter,
		},
		{
			"inet-natsource-forward",
			"natsource-forward chain should be invalid: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_INET, exprs.NFT_CHAIN_NATSOURCE, exprs.NFT_HOOK_FORWARD,
			true,
			nil, nftables.ChainTypeFilter,
		},
		{
			"netdev-natsource-forward",
			"netdev chain should be invalid: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_NETDEV, exprs.NFT_CHAIN_NATSOURCE, exprs.NFT_HOOK_FORWARD,
			true,
			nil,
			nftables.ChainTypeFilter,
		},
		{
			"arp-natsource-forward",
			"arp chain should be invalid: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_ARP, exprs.NFT_CHAIN_NATSOURCE, exprs.NFT_HOOK_FORWARD,
			true,
			nil, nftables.ChainTypeFilter,
		},
		{
			"bridge-natsource-forward",
			"bridge chain should be invalid: %+v-%+v <-> %v-%v",
			exprs.NFT_FAMILY_ARP, exprs.NFT_CHAIN_NATSOURCE, exprs.NFT_HOOK_FORWARD,
			true,
			nil, nftables.ChainTypeFilter,
		},
	}

	for _, testChainPrio := range matrixTests {
		t.Run(testChainPrio.test, func(t *testing.T) {
			chainPrio, chainType := nftb.GetChainPriority(testChainPrio.family, testChainPrio.chain, testChainPrio.hook)

			if testChainPrio.checkEqual {
				if chainPrio != testChainPrio.chainPrio && chainType != testChainPrio.chainType {
				}
			} else {
				if chainPrio == testChainPrio.chainPrio && chainType == testChainPrio.chainType {
					t.Errorf(testChainPrio.errorReason, chainPrio, chainType, testChainPrio.chainPrio, testChainPrio.chainType)
				}
			}
		})
	}

}
