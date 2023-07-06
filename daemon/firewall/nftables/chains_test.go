package nftables_test

import (
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables"
)

func TestChains(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	if nftest.Fw.AddInterceptionTables() != nil {
		t.Error("Error adding interception tables")
	}

	t.Run("AddChain", func(t *testing.T) {
		filterPolicy := nftables.ChainPolicyAccept
		chn := nftest.Fw.AddChain(
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
		if !nftest.Fw.Commit() {
			t.Error("error adding input-filter-inet chain")
		}
	})

	t.Run("getChain", func(t *testing.T) {
		tblfilter := nftest.Fw.GetTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
		if tblfilter == nil {
			t.Error("table filter-inet not created")
		}

		chn := nftest.Fw.GetChain(exprs.NFT_HOOK_INPUT, tblfilter, exprs.NFT_FAMILY_INET)
		if chn == nil {
			t.Error("chain input-filter-inet not added")
		}
	})

	t.Run("delChain", func(t *testing.T) {
		tblfilter := nftest.Fw.GetTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
		if tblfilter == nil {
			t.Error("table filter-inet not created")
		}

		chn := nftest.Fw.GetChain(exprs.NFT_HOOK_INPUT, tblfilter, exprs.NFT_FAMILY_INET)
		if chn == nil {
			t.Error("chain input-filter-inet not added")
		}

		if err := nftest.Fw.DelChain(chn); err != nil {
			t.Error("error deleting chain input-filter-inet")
		}
	})

	nftest.Fw.DelSystemTables()
}

// TestAddInterceptionChains checks if the needed tables and chains have been created.
// We use 2: output-mangle-inet for intercepting outbound connections, and input-filter-inet for DNS responses interception
func TestAddInterceptionChains(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	if err := nftest.Fw.AddInterceptionTables(); err != nil {
		t.Errorf("Error adding interception tables: %s", err)
	}

	if err := nftest.Fw.AddInterceptionChains(); err != nil {
		t.Errorf("Error adding interception chains: %s", err)
	}

	nftest.Fw.DelSystemTables()
}
