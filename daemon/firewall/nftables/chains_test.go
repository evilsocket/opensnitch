package nftables

import (
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/google/nftables"
)

func TestChains(t *testing.T) {
	conn, newNS = OpenSystemConn(t)
	defer CleanupSystemConn(t, newNS)
	nft.conn = conn

	if nft.addInterceptionTables() != nil {
		t.Error("Error adding interception tables")
	}

	t.Run("AddChain", func(t *testing.T) {
		filterPolicy := nftables.ChainPolicyAccept
		chn := nft.AddChain(
			exprs.NFT_HOOK_INPUT,
			exprs.NFT_CHAIN_FILTER,
			exprs.NFT_FAMILY_INET,
			nftables.ChainPriorityFilter,
			nftables.ChainTypeFilter,
			nftables.ChainHookInput,
			filterPolicy)
		if chn == nil {
			t.Error("chain input-filter-inet not created")
		}
		if !nft.Commit() {
			t.Error("error adding input-filter-inet chain")
		}
	})

	t.Run("getChain", func(t *testing.T) {
		tblfilter := nft.getTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
		if tblfilter == nil {
			t.Error("table filter-inet not created")
		}

		chn := nft.getChain(exprs.NFT_HOOK_INPUT, tblfilter, exprs.NFT_FAMILY_INET)
		if chn == nil {
			t.Error("chain input-filter-inet not added")
		}
	})

	t.Run("delChain", func(t *testing.T) {
		tblfilter := nft.getTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
		if tblfilter == nil {
			t.Error("table filter-inet not created")
		}

		chn := nft.getChain(exprs.NFT_HOOK_INPUT, tblfilter, exprs.NFT_FAMILY_INET)
		if chn == nil {
			t.Error("chain input-filter-inet not added")
		}

		if err := nft.delChain(chn); err != nil {
			t.Error("error deleting chain input-filter-inet")
		}
	})

	nft.delSystemTables()
}

// TestAddInterceptionChains checks if the needed tables and chains have been created.
// We use 2: output-mangle-inet for intercepting outbound connections, and input-filter-inet for DNS responses interception
func TestAddInterceptionChains(t *testing.T) {
	if err := nft.addInterceptionTables(); err != nil {
		t.Errorf("Error adding interception tables: %s", err)
	}

	if err := nft.addInterceptionChains(); err != nil {
		t.Errorf("Error adding interception chains: %s", err)
	}

	nft.delSystemTables()
}
