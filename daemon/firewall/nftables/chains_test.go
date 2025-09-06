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
			exprs.TABLE_OPENSNITCH,
			exprs.NFT_FAMILY_INET,
			nftables.ChainPriorityFilter,
			nftables.ChainTypeFilter,
			nftables.ChainHookInput,
			filterPolicy)
		if chn == nil {
			t.Error("chain input-opensnitch-inet not created")
		}
		if !nftest.Fw.Commit() {
			t.Error("error adding input-opensnitch-inet chain")
		}
	})

	t.Run("getChain", func(t *testing.T) {
		tblfilter := nftest.Fw.GetTable(exprs.TABLE_OPENSNITCH, exprs.NFT_FAMILY_INET)
		if tblfilter == nil {
			t.Error("table opensnitch-inet not created")
		}

		chn := nftest.Fw.GetChain(exprs.NFT_HOOK_INPUT, tblfilter, exprs.NFT_FAMILY_INET)
		if chn == nil {
			t.Error("chain input-opensnitch-inet not added")
		}
	})

	t.Run("delChain", func(t *testing.T) {
		tblfilter := nftest.Fw.GetTable(exprs.TABLE_OPENSNITCH, exprs.NFT_FAMILY_INET)
		if tblfilter == nil {
			t.Error("table opensnitch-inet not created")
		}

		chn := nftest.Fw.GetChain(exprs.NFT_HOOK_INPUT, tblfilter, exprs.NFT_FAMILY_INET)
		if chn == nil {
			t.Error("chain input-opensnitch-inet not added")
		}

		if err := nftest.Fw.DelChain(chn); err != nil {
			t.Error("error deleting chain input-opensnitch-inet")
		}
	})

	nftest.Fw.DelSystemTables()
}

// TestAddInterceptionChains checks if the needed tables and chains have been created.
// We use 2: intercept_con-opensnitch-inet for intercepting outbound connections, and intercept_dns-opensnitch-inet for DNS responses interception
/*func TestAddInterceptionChains(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	if err := nftest.Fw.AddInterceptionTables(); err != nil {
		t.Errorf("Error adding interception tables: %s", err)
	}

	if err := nftest.Fw.AddInterceptionChains(); err != nil {
		t.Errorf("Error adding interception chains: %s", err)
	}

	nftest.Fw.DelSystemTables()
}*/
