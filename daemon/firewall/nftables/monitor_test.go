package nftables_test

import (
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	nftb "github.com/evilsocket/opensnitch/daemon/firewall/nftables"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables"
)

// mimic EnableInterception() but without NewRulesChecker()
func addInterceptionRules(nft *nftb.Nft, t *testing.T) {
	if err := nft.AddInterceptionTables(); err != nil {
		t.Errorf("Error while adding interception tables: %s", err)
		return
	}
	if err := nft.AddInterceptionChains(); err != nil {
		t.Errorf("Error while adding interception chains: %s", err)
		return
	}

	if err, _ := nft.QueueDNSResponses(common.EnableRule, common.EnableRule); err != nil {
		t.Errorf("Error while running DNS nftables rule: %s", err)
	}
	if err, _ := nft.QueueConnections(common.EnableRule, common.EnableRule); err != nil {
		t.Errorf("Error while running conntrack nftables rule: %s", err)
	}
}

func _testMonitorReload(t *testing.T, conn *nftables.Conn, nft *nftb.Nft) {
	tblfilter := nft.GetTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
	if tblfilter == nil || tblfilter.Name != exprs.NFT_CHAIN_FILTER {
		t.Error("table filter-inet not in the list")
	}
	chnFilterInput := nftest.Fw.GetChain(exprs.NFT_HOOK_INPUT, tblfilter, exprs.NFT_FAMILY_INET)
	if chnFilterInput == nil {
		t.Error("chain input-filter-inet not in the list")
	}
	rules, _ := conn.GetRules(tblfilter, chnFilterInput)
	if len(rules) == 0 {
		t.Error("DNS interception rule not added")
	}
	conn.FlushChain(chnFilterInput)
	nftest.Fw.Commit()

	// the rules checker checks the rules every 10s
	reloaded := false
	for i := 0; i < 15; i++ {
		if r, _ := getRule(t, conn, tblfilter.Name, exprs.NFT_HOOK_INPUT, nftb.InterceptionRuleKey, 0); r != nil {
			reloaded = true
			break
		}
		time.Sleep(time.Second)
	}
	if !reloaded {
		t.Error("rules under input-filter-inet not reloaded after 10s")
	}
}

func TestAreRulesLoaded(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	addInterceptionRules(nftest.Fw, t)
	if !nftest.Fw.AreRulesLoaded() {
		t.Error("interception rules not loaded, and they should")
	}

	nftest.Fw.DelInterceptionRules()
	if nftest.Fw.AreRulesLoaded() {
		t.Error("interception rules are loaded, and the shouldn't")
	}
}

func TestMonitorReload(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	nftest.Fw.SetRulesCheckerInterval("10s")
	nftest.Fw.EnableInterception()

	// test that rules are reloaded after being deleted, but also
	// that the monitor is not stopped after the first reload.
	_testMonitorReload(t, conn, nftest.Fw)
	_testMonitorReload(t, conn, nftest.Fw)
	_testMonitorReload(t, conn, nftest.Fw)
}
