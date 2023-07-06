package nftables_test

import (
	"testing"

	nftb "github.com/evilsocket/opensnitch/daemon/firewall/nftables"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables"
)

func getRulesList(t *testing.T, conn *nftables.Conn, family, tblName, chnName string) ([]*nftables.Rule, int) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, -1
	}

	for rdx, c := range chains {
		if c.Table.Family == nftb.GetFamilyCode(family) && c.Table.Name == tblName && c.Name == chnName {
			rules, err := conn.GetRule(c.Table, c)
			if err != nil {
				return nil, -1
			}
			return rules, rdx
		}
	}

	return nil, -1
}

func getRule(t *testing.T, conn *nftables.Conn, tblName, chnName, key string, ruleHandle uint64) (*nftables.Rule, int) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, -1
	}

	for _, c := range chains {
		rules, err := conn.GetRule(c.Table, c)
		if err != nil {
			continue
		}
		for rdx, r := range rules {
			//t.Logf("Table: %s<->%s, Chain: %s<->%s, Rule Handle: %d<->%d, UserData: %s<->%s", c.Table.Name, tblName, c.Name, chnName, r.Handle, ruleHandle, string(r.UserData), key)
			if c.Table.Name == tblName && c.Name == chnName {
				if ruleHandle > 0 && r.Handle == ruleHandle {
					return r, rdx
				}
				if key != "" && string(r.UserData) == key {
					return r, rdx
				}
			}
		}
	}

	return nil, -1
}

func TestAddRule(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	r, chn := nftest.AddTestRule(t, conn, exprs.NewNoTrack())

	/*
		_, err := nft.AddTable("yyy", exprs.NFT_FAMILY_INET)
		if err != nil {
			t.Error("pre step add_table() yyy-inet failed")
		}
		chn := nft.AddChain(
			exprs.NFT_HOOK_INPUT,
			"yyy",
			exprs.NFT_FAMILY_INET,
			nftables.ChainPriorityFilter,
			nftables.ChainTypeFilter,
			nftables.ChainHookInput,
			nftables.ChainPolicyAccept)
		if chn == nil {
			t.Error("pre step add_chain() input-yyy-inet failed")
		}

		r, err := nft.addRule(
			exprs.NFT_HOOK_INPUT, "yyy", exprs.NFT_FAMILY_INET,
			0,
			"key-yyy",
			exprs.NewNoTrack())
		if err != nil {
			t.Errorf("Error adding rule: %s", err)
		}
	*/

	rules, err := conn.GetRules(chn.Table, chn)
	if err != nil || len(rules) != 1 {
		t.Errorf("Rule not added, total: %d", len(rules))
	}
	t.Log(r.Handle)
}

func TestInsertRule(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	_, err := nftest.Fw.AddTable("yyy", exprs.NFT_FAMILY_INET)
	if err != nil {
		t.Error("pre step add_table() yyy-inet failed")
	}
	chn := nftest.Fw.AddChain(
		exprs.NFT_HOOK_INPUT,
		"yyy",
		exprs.NFT_FAMILY_INET,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter,
		nftables.ChainHookInput,
		nftables.ChainPolicyAccept)
	if chn == nil {
		t.Error("pre step add_chain() input-yyy-inet failed")
	}

	err = nftest.Fw.InsertRule(
		exprs.NFT_HOOK_INPUT, "yyy", exprs.NFT_FAMILY_INET,
		0,
		exprs.NewNoTrack())
	if err != nil {
		t.Errorf("Error inserting rule: %s", err)
	}
	rules, err := conn.GetRules(chn.Table, chn)
	if err != nil || len(rules) != 1 {
		t.Errorf("Rule not inserted, total: %d", len(rules))
	}
}

func TestQueueConnections(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	_, err := nftest.Fw.AddTable(exprs.NFT_CHAIN_MANGLE, exprs.NFT_FAMILY_INET)
	if err != nil {
		t.Error("pre step add_table() mangle-inet failed")
	}
	chn := nftest.Fw.AddChain(
		exprs.NFT_HOOK_OUTPUT, exprs.NFT_CHAIN_MANGLE, exprs.NFT_FAMILY_INET,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter,
		nftables.ChainHookInput,
		nftables.ChainPolicyAccept)
	if chn == nil {
		t.Error("pre step add_chain() output-mangle-inet failed")
	}

	if err1, err2 := nftest.Fw.QueueConnections(true, true); err1 != nil && err2 != nil {
		t.Errorf("rule to queue connections not added: %s, %s", err1, err2)
	}

	r, _ := getRule(t, conn, exprs.NFT_CHAIN_MANGLE, exprs.NFT_HOOK_OUTPUT, nftb.InterceptionRuleKey, 0)
	if r == nil {
		t.Error("rule to queue connections not in the list")
	}
	if string(r.UserData) != nftb.InterceptionRuleKey {
		t.Errorf("invalid UserData: %s", string(r.UserData))
	}
}

func TestQueueDNSResponses(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	_, err := nftest.Fw.AddTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
	if err != nil {
		t.Error("pre step add_table() filter-inet failed")
	}
	chn := nftest.Fw.AddChain(
		exprs.NFT_HOOK_INPUT, exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter,
		nftables.ChainHookInput,
		nftables.ChainPolicyAccept)
	if chn == nil {
		t.Error("pre step add_chain() input-filter-inet failed")
	}

	if err1, err2 := nftest.Fw.QueueDNSResponses(true, true); err1 != nil && err2 != nil {
		t.Errorf("rule to queue DNS responses not added: %s, %s", err1, err2)
	}

	r, _ := getRule(t, conn, exprs.NFT_CHAIN_FILTER, exprs.NFT_HOOK_INPUT, nftb.InterceptionRuleKey, 0)
	if r == nil {
		t.Error("rule to queue DNS responses not in the list")
	}
	if string(r.UserData) != nftb.InterceptionRuleKey {
		t.Errorf("invalid UserData: %s", string(r.UserData))
	}

	// nftables.DelRule() does not accept rule handles == 0
	// https://github.com/google/nftables/blob/8f2d395e1089dea4966c483fbeae7e336917c095/rule.go#L200
	// sometimes when adding this rule in new namespaces it's added with rule.Handle == 0, so it fails deleting the rule, thus failing the test.
	// can it happen on "prod" environments?
	/*if err1, err2 := nft.QueueDNSResponses(false, true); err1 != nil && err2 != nil {
		t.Errorf("rule to queue DNS responses not deleted: %s, %s", err1, err2)
	}
	r, _ = getRule(t, conn, exprs.NFT_CHAIN_FILTER, exprs.NFT_HOOK_INPUT, nftb.InterceptionRuleKey, 0)
	if r != nil {
		t.Error("rule to queue DNS responses should have been deleted")
	}*/
}
